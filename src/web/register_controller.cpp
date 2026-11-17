// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder
//
// register_controller — 游戏内账号注册·提交（Prontera 私服定制，2026-11-17）
//
// 职责划分（ADR-0004 玩家 HTTP 端点单一 seam）：
//   - 本控制器拥有账号创建的写入权：login 表在服务端侧的唯一写者；
//   - 验证码签发 / 发信 / 限频在 remote-client api/register.php（邮件 adapter，
//     对 login 表只读）；两侧以 reg_verify 表为接缝；
//   - 客户端经 nginx 同源 /api/register/submit（剥 /api/ 前缀）到达本控制器。
//
// 密码按 per-account 机制落库（09_user_salt.sql / login.cpp 同方案）：
//   user_salt = 16 字符 hex 随机盐；user_pass = MD5(user_salt + 原文)。
//
// 错误响应对齐 ticket 惯例：HTTP 400 + {"error":"code"}；中文文案由客户端映射。

#include "register_controller.hpp"

#include <string>

#include <nlohmann/json.hpp>

#include <common/md5calc.hpp>
#include <common/random.hpp>
#include <common/showmsg.hpp>
#include <common/sql.hpp>

#include "http.hpp"
#include "sqllock.hpp"
#include "web.hpp"

namespace {

constexpr int CODE_TTL = 600;             // 验证码有效期（秒），与 PHP 发码侧一致
constexpr int MAX_CODE_TRIES = 5;         // 验证码最大错误次数，超过作废
constexpr size_t MAX_USERNAME_LEN = 23;   // login.userid varchar(23)
constexpr size_t MAX_EMAIL_LEN = 39;
constexpr size_t MAX_PASSWORD_LEN = 23;
constexpr size_t MIN_PASSWORD_LEN = 6;
constexpr size_t SALT_LEN = 16;           // 16 字符 hex，与 09_user_salt.sql 迁移示例同构

/** 参数安全读取（POST form 字段） */
std::string field(const Request &req, const char *name, const std::string &def = "") {
	if (!req.has_file(name))
		return def;
	return req.get_file_value(name).content;
}

void respond_error(Response &res, const char *code) {
	res.status = HTTP_BAD_REQUEST;
	nlohmann::json j;
	j["error"] = code;
	res.set_content(j.dump(), "application/json");
}

bool valid_username(const std::string &u) {
	if (u.size() < 4 || u.size() > MAX_USERNAME_LEN)
		return false;
	for (char c : u) {
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
			return false;
	}
	return true;
}

/** 务实校验（格式规则的权威门在发码侧 PHP FILTER_VALIDATE_EMAIL；此处为提交侧兜底） */
bool valid_email(const std::string &e) {
	if (e.empty() || e.size() > MAX_EMAIL_LEN)
		return false;
	size_t at = e.find('@');
	if (at == std::string::npos || at == 0 || at == e.size() - 1)
		return false;
	if (e.find('@', at + 1) != std::string::npos)
		return false;
	size_t dot = e.find('.', at);
	if (dot == std::string::npos || dot == at + 1 || dot == e.size() - 1)
		return false;
	for (char c : e) {
		if (c == ' ' || static_cast<unsigned char>(c) < 0x20)
			return false;
	}
	return true;
}

bool valid_password(const std::string &p) {
	return p.size() >= MIN_PASSWORD_LEN && p.size() <= MAX_PASSWORD_LEN;
}

/** 常量时间比较（6 位验证码；防时序侧信道，成本可忽略） */
bool constant_time_equals(const std::string &a, const std::string &b) {
	if (a.size() != b.size())
		return false;
	volatile unsigned char diff = 0;
	for (size_t i = 0; i < a.size(); i++)
		diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
	return diff == 0;
}

/** 16 字符 hex 随机盐 */
std::string generate_salt() {
	static const char hex[] = "0123456789abcdef";
	std::string salt;
	salt.reserve(SALT_LEN);
	for (size_t i = 0; i < SALT_LEN; i++)
		salt.push_back(hex[rnd() % 16]);
	return salt;
}

} // namespace

/**
 * POST /register/submit
 * 字段：username, email, password, password2, sex(M/F), code
 * 成功：200 {"ok":true,"username":"..."}；失败：400 {"error":"code"}
 */
HANDLER_FUNC(register_submit) {
	std::string username = field(req, "username");
	std::string email = field(req, "email");
	std::string password = field(req, "password");
	std::string password2 = field(req, "password2");
	std::string sex = field(req, "sex");
	std::string code = field(req, "code");

	// 输入校验（提交侧权威终检；客户端与发码侧各有初步校验）
	if (!valid_username(username)) { respond_error(res, "bad_username"); return; }
	if (!valid_email(email))       { respond_error(res, "bad_email"); return; }
	if (!valid_password(password)) { respond_error(res, "bad_password"); return; }
	if (password != password2)     { respond_error(res, "password_mismatch"); return; }
	if (sex != "M" && sex != "F")  { respond_error(res, "bad_sex"); return; }
	if (code.size() != 6)          { respond_error(res, "bad_code"); return; }
	for (char c : code) {
		if (c < '0' || c > '9')    { respond_error(res, "bad_code"); return; }
	}

	SQLLock sl(LOGIN_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();

	// 验证码行检查（reg_verify 与 login 同库，接缝表见 ADR-0004）
	char stored_code[8] = "";
	int32 tries = 0;
	int32 updated_at = 0;
	{
		SqlStmt stmt{ *handle };
		bool qok = SQL_SUCCESS == stmt.Prepare(
				"SELECT `code`, `tries`, `updated_at` FROM `reg_verify` WHERE `email` = ? LIMIT 1")
			&& SQL_SUCCESS == stmt.BindParam(0, SQLDT_STRING, (void *)email.c_str(), email.length())
			&& SQL_SUCCESS == stmt.Execute()
			&& SQL_SUCCESS == stmt.BindColumn(0, SQLDT_STRING, stored_code, sizeof(stored_code))
			&& SQL_SUCCESS == stmt.BindColumn(1, SQLDT_INT32, &tries, sizeof(tries))
			&& SQL_SUCCESS == stmt.BindColumn(2, SQLDT_INT32, &updated_at, sizeof(updated_at));
		if (!qok) {
			SqlStmt_ShowDebug(stmt);
			sl.unlock();
			res.status = 500;
			res.set_content("Error", "text/plain");
			return;
		}
		if (SQL_SUCCESS != stmt.NextRow()) {
			sl.unlock();
			respond_error(res, "no_code");
			return;
		}
	}

	// 有效期
	if (time(nullptr) - updated_at > CODE_TTL) {
		SqlStmt del{ *handle };
		if (SQL_SUCCESS == del.Prepare("DELETE FROM `reg_verify` WHERE `email` = ?")
			&& SQL_SUCCESS == del.BindParam(0, SQLDT_STRING, (void *)email.c_str(), email.length())
			&& SQL_SUCCESS == del.Execute()) {
			// 过期行清理成功与否不影响响应
		}
		sl.unlock();
		respond_error(res, "code_expired");
		return;
	}

	// 错误次数超限 → 作废
	if (tries >= MAX_CODE_TRIES) {
		SqlStmt del{ *handle };
		if (SQL_SUCCESS == del.Prepare("DELETE FROM `reg_verify` WHERE `email` = ?")
			&& SQL_SUCCESS == del.BindParam(0, SQLDT_STRING, (void *)email.c_str(), email.length())
			&& SQL_SUCCESS == del.Execute()) {
			// 同上
		}
		sl.unlock();
		respond_error(res, "code_locked");
		return;
	}

	// 占用终检（发码后到提交前可能被抢先）
	{
		SqlStmt stmt{ *handle };
		int32 exists = 0;
		bool qok = SQL_SUCCESS == stmt.Prepare("SELECT COUNT(*) FROM `login` WHERE `userid` = ?")
			&& SQL_SUCCESS == stmt.BindParam(0, SQLDT_STRING, (void *)username.c_str(), username.length())
			&& SQL_SUCCESS == stmt.Execute()
			&& SQL_SUCCESS == stmt.BindColumn(0, SQLDT_INT32, &exists, sizeof(exists))
			&& SQL_SUCCESS == stmt.NextRow();
		if (!qok) {
			SqlStmt_ShowDebug(stmt);
			sl.unlock();
			res.status = 500;
			res.set_content("Error", "text/plain");
			return;
		}
		if (exists > 0) {
			sl.unlock();
			respond_error(res, "username_taken");
			return;
		}
	}
	{
		SqlStmt stmt{ *handle };
		int32 exists = 0;
		bool qok = SQL_SUCCESS == stmt.Prepare("SELECT COUNT(*) FROM `login` WHERE `email` = ?")
			&& SQL_SUCCESS == stmt.BindParam(0, SQLDT_STRING, (void *)email.c_str(), email.length())
			&& SQL_SUCCESS == stmt.Execute()
			&& SQL_SUCCESS == stmt.BindColumn(0, SQLDT_INT32, &exists, sizeof(exists))
			&& SQL_SUCCESS == stmt.NextRow();
		if (!qok) {
			SqlStmt_ShowDebug(stmt);
			sl.unlock();
			res.status = 500;
			res.set_content("Error", "text/plain");
			return;
		}
		if (exists > 0) {
			sl.unlock();
			respond_error(res, "email_taken");
			return;
		}
	}

	// 验证码比对（错误计次）
	if (!constant_time_equals(std::string(stored_code), code)) {
		SqlStmt up{ *handle };
		if (SQL_SUCCESS != up.Prepare("UPDATE `reg_verify` SET `tries` = `tries` + 1 WHERE `email` = ?")
			|| SQL_SUCCESS != up.BindParam(0, SQLDT_STRING, (void *)email.c_str(), email.length())
			|| SQL_SUCCESS != up.Execute()) {
			SqlStmt_ShowDebug(up);
		}
		sl.unlock();
		respond_error(res, "code_wrong");
		return;
	}

	// 建号：user_pass = MD5(user_salt + 原文)，与 login.cpp 校验分支同方案
	std::string salt = generate_salt();
	std::string hashed;
	hashed.reserve(SALT_LEN + password.length());
	hashed.append(salt);
	hashed.append(password);
	char md5str[32 + 1];
	MD5_String(hashed.c_str(), md5str);
	std::string pass_hash(md5str);
	std::string last_ip = req.remote_addr.empty() ? std::string("-") : req.remote_addr;

	{
		SqlStmt ins{ *handle };
		if (SQL_SUCCESS != ins.Prepare(
				"INSERT INTO `login` (`userid`, `user_pass`, `user_salt`, `sex`, `email`, `group_id`, `state`, `last_ip`, `logincount`)"
				" VALUES (?, ?, ?, ?, ?, 0, 0, ?, 0)")
			|| SQL_SUCCESS != ins.BindParam(0, SQLDT_STRING, (void *)username.c_str(), username.length())
			|| SQL_SUCCESS != ins.BindParam(1, SQLDT_STRING, (void *)pass_hash.c_str(), pass_hash.length())
			|| SQL_SUCCESS != ins.BindParam(2, SQLDT_STRING, (void *)salt.c_str(), salt.length())
			|| SQL_SUCCESS != ins.BindParam(3, SQLDT_STRING, (void *)sex.c_str(), sex.length())
			|| SQL_SUCCESS != ins.BindParam(4, SQLDT_STRING, (void *)email.c_str(), email.length())
			|| SQL_SUCCESS != ins.BindParam(5, SQLDT_STRING, (void *)last_ip.c_str(), last_ip.length())
			|| SQL_SUCCESS != ins.Execute()
		) {
			SqlStmt_ShowDebug(ins);
			sl.unlock();
			// 多为 userid 唯一键撞车（终检后瞬间被抢先）或 email 超长被拒
			respond_error(res, "register_failed");
			return;
		}
	}

	// 验证码用后作废
	{
		SqlStmt del{ *handle };
		if (SQL_SUCCESS == del.Prepare("DELETE FROM `reg_verify` WHERE `email` = ?")
			&& SQL_SUCCESS == del.BindParam(0, SQLDT_STRING, (void *)email.c_str(), email.length())
			&& SQL_SUCCESS == del.Execute()) {
			// 用后作废失败仅浪费一次可用验证码，不影响建号结果
		}
	}
	sl.unlock();

	nlohmann::json j;
	j["ok"] = true;
	j["username"] = username;
	res.set_content(j.dump(), "application/json");
}
