// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder
//
// ticket_controller — 游戏内客服工单（Prontera 私服定制，2026-11-10）
//
// 玩家在客户端 UI（Plugins/SupportCenter）提交/查看工单，经 nginx
// 同源反代（client/nginx.conf location /ticket）到本控制器；鉴权复用
// isAuthorized（login.web_auth_token，与 /userconfig 同链路）。
// 数据在 ops 库（运营域），GM 处理走 ops-dashboard 管理页。
//
// 限制：每账号未关闭工单 ≤3（防灌水）；subject ≤120、message ≤2000 字符。

#include "ticket_controller.hpp"

#include <string>
#include <nlohmann/json.hpp>

#include <common/showmsg.hpp>
#include <common/sql.hpp>

#include "auth.hpp"
#include "http.hpp"
#include "sqllock.hpp"
#include "webutils.hpp"
#include "web.hpp"

namespace {

constexpr int MAX_OPEN_TICKETS = 3;
constexpr size_t MAX_SUBJECT_LEN = 120;
constexpr size_t MAX_MESSAGE_LEN = 2000;

/** 参数安全读取（POST form 字段） */
std::string field(const Request &req, const char *name, const std::string &def = "") {
	if (!req.has_file(name))
		return def;
	return req.get_file_value(name).content;
}

/** 工单归属校验：ticket 存在且属于 account_id。out_status 返回工单状态 */
bool ticket_belongs(int64 ticket_id, int32 account_id, char *out_status, size_t status_len) {
	SQLLock sl(WEB_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();
	SqlStmt stmt{ *handle };
	if (SQL_SUCCESS != stmt.Prepare(
			"SELECT `status` FROM `ops`.`ops_tickets` WHERE (`id` = ? AND `account_id` = ?) LIMIT 1")
		|| SQL_SUCCESS != stmt.BindParam(0, SQLDT_INT64, &ticket_id, sizeof(ticket_id))
		|| SQL_SUCCESS != stmt.BindParam(1, SQLDT_INT32, &account_id, sizeof(account_id))
		|| SQL_SUCCESS != stmt.Execute()
	) {
		SqlStmt_ShowDebug(stmt);
		sl.unlock();
		return false;
	}
	if (SQL_SUCCESS != stmt.BindColumn(0, SQLDT_STRING, out_status, status_len)
		|| SQL_SUCCESS != stmt.NextRow()
	) {
		sl.unlock();
		return false;
	}
	sl.unlock();
	return true;
}

} // namespace

// ─── 创建工单 ───────────────────────────────────────────────────────────────

HANDLER_FUNC(ticket_create) {
	if (!isAuthorized(req, false)) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("Error", "text/plain");
		return;
	}
	auto account_id = std::stoi(field(req, "AID"));
	auto char_id = std::stoi(field(req, "CID", "0"));
	auto char_name = field(req, "CharName");
	auto subject = field(req, "subject");
	auto message = field(req, "message");

	if (subject.empty() || message.empty()) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("{\"error\":\"empty\"}", "application/json");
		return;
	}
	if (subject.length() > MAX_SUBJECT_LEN)
		subject = subject.substr(0, MAX_SUBJECT_LEN);
	if (message.length() > MAX_MESSAGE_LEN)
		message = message.substr(0, MAX_MESSAGE_LEN);

	SQLLock sl(WEB_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();

	// 未关闭工单数量限制
	SqlStmt cnt{ *handle };
	int32 open_count = 0;
	if (SQL_SUCCESS != cnt.Prepare(
			"SELECT COUNT(*) AS c FROM `ops`.`ops_tickets` WHERE (`account_id` = ? AND `status` != 'closed')")
		|| SQL_SUCCESS != cnt.BindParam(0, SQLDT_INT32, &account_id, sizeof(account_id))
		|| SQL_SUCCESS != cnt.Execute()
		|| SQL_SUCCESS != cnt.BindColumn(0, SQLDT_INT32, &open_count, sizeof(open_count))
		|| SQL_SUCCESS != cnt.NextRow()
	) {
		SqlStmt_ShowDebug(cnt);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}
	if (open_count >= MAX_OPEN_TICKETS) {
		sl.unlock();
		res.status = HTTP_BAD_REQUEST;
		res.set_content("{\"error\":\"limit\"}", "application/json");
		return;
	}

	// 插入工单 + 首条消息
	SqlStmt ins{ *handle };
	if (SQL_SUCCESS != ins.Prepare(
			"INSERT INTO `ops`.`ops_tickets` (`account_id`, `char_id`, `char_name`, `subject`, `status`) VALUES (?, ?, ?, ?, 'open')")
		|| SQL_SUCCESS != ins.BindParam(0, SQLDT_INT32, &account_id, sizeof(account_id))
		|| SQL_SUCCESS != ins.BindParam(1, SQLDT_INT32, &char_id, sizeof(char_id))
		|| SQL_SUCCESS != ins.BindParam(2, SQLDT_STRING, (void *)char_name.c_str(), char_name.length())
		|| SQL_SUCCESS != ins.BindParam(3, SQLDT_STRING, (void *)subject.c_str(), subject.length())
		|| SQL_SUCCESS != ins.Execute()
	) {
		SqlStmt_ShowDebug(ins);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}
	int64 ticket_id = (int64)Sql_LastInsertId(handle);

	SqlStmt insmsg{ *handle };
	if (SQL_SUCCESS != insmsg.Prepare(
			"INSERT INTO `ops`.`ops_ticket_messages` (`ticket_id`, `sender`, `message`) VALUES (?, 'player', ?)")
		|| SQL_SUCCESS != insmsg.BindParam(0, SQLDT_INT64, &ticket_id, sizeof(ticket_id))
		|| SQL_SUCCESS != insmsg.BindParam(1, SQLDT_STRING, (void *)message.c_str(), message.length())
		|| SQL_SUCCESS != insmsg.Execute()
	) {
		SqlStmt_ShowDebug(insmsg);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}
	sl.unlock();

	nlohmann::json j;
	j["id"] = ticket_id;
	j["status"] = "open";
	res.set_content(j.dump(), "application/json");
}

// ─── 我的工单列表 ───────────────────────────────────────────────────────────

HANDLER_FUNC(ticket_list) {
	if (!isAuthorized(req, false)) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("Error", "text/plain");
		return;
	}
	auto account_id = std::stoi(field(req, "AID"));

	SQLLock sl(WEB_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();
	SqlStmt stmt{ *handle };
	// 最后一条消息预览（LEFT JOIN 取最大 id 的消息内容——MySQL 8 允许
	// 先聚合子查询再 JOIN，避免 ONLY_FULL_GROUP_BY 报错）
	if (SQL_SUCCESS != stmt.Prepare(
			"SELECT t.`id`, t.`subject`, t.`status`, t.`updated_at`, m.`message` "
			"FROM `ops`.`ops_tickets` t "
			"LEFT JOIN `ops`.`ops_ticket_messages` m ON m.`id` = ("
			"  SELECT MAX(m2.`id`) FROM `ops`.`ops_ticket_messages` m2 WHERE m2.`ticket_id` = t.`id`) "
			"WHERE t.`account_id` = ? ORDER BY t.`updated_at` DESC LIMIT 20")
		|| SQL_SUCCESS != stmt.BindParam(0, SQLDT_INT32, &account_id, sizeof(account_id))
		|| SQL_SUCCESS != stmt.Execute()
	) {
		SqlStmt_ShowDebug(stmt);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}

	char id_buf[32], subject_buf[256], status_buf[16], updated_buf[32], msg_buf[2048];
	if (SQL_SUCCESS != stmt.BindColumn(0, SQLDT_STRING, &id_buf, sizeof(id_buf))
		|| SQL_SUCCESS != stmt.BindColumn(1, SQLDT_STRING, &subject_buf, sizeof(subject_buf))
		|| SQL_SUCCESS != stmt.BindColumn(2, SQLDT_STRING, &status_buf, sizeof(status_buf))
		|| SQL_SUCCESS != stmt.BindColumn(3, SQLDT_STRING, &updated_buf, sizeof(updated_buf))
		|| SQL_SUCCESS != stmt.BindColumn(4, SQLDT_STRING, &msg_buf, sizeof(msg_buf))
	) {
		SqlStmt_ShowDebug(stmt);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}

	nlohmann::json arr = nlohmann::json::array();
	while (SQL_SUCCESS == stmt.NextRow()) {
		nlohmann::json item;
		item["id"] = std::stoi(id_buf);
		item["subject"] = subject_buf;
		item["status"] = status_buf;
		item["updated_at"] = updated_buf;
		std::string preview = msg_buf;
		if (preview.length() > 80)
			preview = preview.substr(0, 80) + "...";
		item["preview"] = preview;
		arr.push_back(item);
	}
	sl.unlock();
	res.set_content(arr.dump(), "application/json");
}

// ─── 工单详情（归属校验） ────────────────────────────────────────────────────

HANDLER_FUNC(ticket_detail) {
	if (!isAuthorized(req, false)) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("Error", "text/plain");
		return;
	}
	auto account_id = std::stoi(field(req, "AID"));
	auto ticket_id = (int64)std::stoll(field(req, "ticket_id", "0"));

	char status_buf[16];
	if (!ticket_belongs(ticket_id, account_id, status_buf, sizeof(status_buf))) {
		res.status = HTTP_NOT_FOUND;
		res.set_content("{\"error\":\"not_found\"}", "application/json");
		return;
	}

	SQLLock sl(WEB_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();
	SqlStmt stmt{ *handle };
	if (SQL_SUCCESS != stmt.Prepare(
			"SELECT `sender`, `message`, `created_at` FROM `ops`.`ops_ticket_messages` "
			"WHERE `ticket_id` = ? ORDER BY `id` ASC LIMIT 100")
		|| SQL_SUCCESS != stmt.BindParam(0, SQLDT_INT64, &ticket_id, sizeof(ticket_id))
		|| SQL_SUCCESS != stmt.Execute()
	) {
		SqlStmt_ShowDebug(stmt);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}

	char sender_buf[16], msg_buf[2048], created_buf[32];
	if (SQL_SUCCESS != stmt.BindColumn(0, SQLDT_STRING, &sender_buf, sizeof(sender_buf))
		|| SQL_SUCCESS != stmt.BindColumn(1, SQLDT_STRING, &msg_buf, sizeof(msg_buf))
		|| SQL_SUCCESS != stmt.BindColumn(2, SQLDT_STRING, &created_buf, sizeof(created_buf))
	) {
		SqlStmt_ShowDebug(stmt);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}

	nlohmann::json j;
	j["status"] = status_buf;
	nlohmann::json msgs = nlohmann::json::array();
	while (SQL_SUCCESS == stmt.NextRow()) {
		nlohmann::json m;
		m["sender"] = sender_buf;
		m["message"] = msg_buf;
		m["created_at"] = created_buf;
		msgs.push_back(m);
	}
	j["messages"] = msgs;
	sl.unlock();
	res.set_content(j.dump(), "application/json");
}

// ─── 玩家回复（仅 open/answered 可回复；回复后回到待处理） ─────────────────

HANDLER_FUNC(ticket_reply) {
	if (!isAuthorized(req, false)) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("Error", "text/plain");
		return;
	}
	auto account_id = std::stoi(field(req, "AID"));
	auto ticket_id = (int64)std::stoll(field(req, "ticket_id", "0"));
	auto message = field(req, "message");

	if (message.empty()) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("{\"error\":\"empty\"}", "application/json");
		return;
	}
	if (message.length() > MAX_MESSAGE_LEN)
		message = message.substr(0, MAX_MESSAGE_LEN);

	char status_buf[16];
	if (!ticket_belongs(ticket_id, account_id, status_buf, sizeof(status_buf))) {
		res.status = HTTP_NOT_FOUND;
		res.set_content("{\"error\":\"not_found\"}", "application/json");
		return;
	}
	if (strcmp(status_buf, "closed") == 0) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("{\"error\":\"closed\"}", "application/json");
		return;
	}

	SQLLock sl(WEB_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();
	SqlStmt ins{ *handle };
	if (SQL_SUCCESS != ins.Prepare(
			"INSERT INTO `ops`.`ops_ticket_messages` (`ticket_id`, `sender`, `message`) VALUES (?, 'player', ?)")
		|| SQL_SUCCESS != ins.BindParam(0, SQLDT_INT64, &ticket_id, sizeof(ticket_id))
		|| SQL_SUCCESS != ins.BindParam(1, SQLDT_STRING, (void *)message.c_str(), message.length())
		|| SQL_SUCCESS != ins.Execute()
		|| SQL_SUCCESS != Sql_Query(handle, "UPDATE `ops`.`ops_tickets` SET `status` = 'open' WHERE `id` = %" PRId64, ticket_id)
	) {
		SqlStmt_ShowDebug(ins);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}
	sl.unlock();
	res.set_content("{\"ok\":true}", "application/json");
}

// ─── 玩家关闭自己的工单 ──────────────────────────────────────────────────────

HANDLER_FUNC(ticket_close) {
	if (!isAuthorized(req, false)) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("Error", "text/plain");
		return;
	}
	auto account_id = std::stoi(field(req, "AID"));
	auto ticket_id = (int64)std::stoll(field(req, "ticket_id", "0"));

	char status_buf[16];
	if (!ticket_belongs(ticket_id, account_id, status_buf, sizeof(status_buf))) {
		res.status = HTTP_NOT_FOUND;
		res.set_content("{\"error\":\"not_found\"}", "application/json");
		return;
	}

	SQLLock sl(WEB_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();
	if (SQL_SUCCESS != Sql_Query(handle,
			"UPDATE `ops`.`ops_tickets` SET `status` = 'closed' WHERE `id` = %" PRId64, ticket_id)) {
		Sql_ShowDebug(handle);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}
	sl.unlock();
	res.set_content("{\"ok\":true}", "application/json");
}

// ─── 我的充值订单（跨库只读 ops.ops_recharge_orders） ────────────────────────

HANDLER_FUNC(ticket_orders) {
	if (!isAuthorized(req, false)) {
		res.status = HTTP_BAD_REQUEST;
		res.set_content("Error", "text/plain");
		return;
	}
	auto account_id = std::stoi(field(req, "AID"));

	SQLLock sl(WEB_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();
	SqlStmt stmt{ *handle };
	if (SQL_SUCCESS != stmt.Prepare(
			"SELECT `id`, `amount`, `currency`, `channel`, `status`, `created_at`, `paid_at` "
			"FROM `ops`.`ops_recharge_orders` WHERE `game_account_id` = ? ORDER BY `id` DESC LIMIT 20")
		|| SQL_SUCCESS != stmt.BindParam(0, SQLDT_INT32, &account_id, sizeof(account_id))
		|| SQL_SUCCESS != stmt.Execute()
	) {
		SqlStmt_ShowDebug(stmt);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}

	char id_buf[32], amount_buf[32], currency_buf[16], channel_buf[32], status_buf[16], created_buf[32], paid_buf[32];
	if (SQL_SUCCESS != stmt.BindColumn(0, SQLDT_STRING, &id_buf, sizeof(id_buf))
		|| SQL_SUCCESS != stmt.BindColumn(1, SQLDT_STRING, &amount_buf, sizeof(amount_buf))
		|| SQL_SUCCESS != stmt.BindColumn(2, SQLDT_STRING, &currency_buf, sizeof(currency_buf))
		|| SQL_SUCCESS != stmt.BindColumn(3, SQLDT_STRING, &channel_buf, sizeof(channel_buf))
		|| SQL_SUCCESS != stmt.BindColumn(4, SQLDT_STRING, &status_buf, sizeof(status_buf))
		|| SQL_SUCCESS != stmt.BindColumn(5, SQLDT_STRING, &created_buf, sizeof(created_buf))
		|| SQL_SUCCESS != stmt.BindColumn(6, SQLDT_STRING, &paid_buf, sizeof(paid_buf))
	) {
		SqlStmt_ShowDebug(stmt);
		sl.unlock();
		res.status = 500;
		res.set_content("Error", "text/plain");
		return;
	}

	nlohmann::json arr = nlohmann::json::array();
	while (SQL_SUCCESS == stmt.NextRow()) {
		nlohmann::json item;
		item["id"] = std::stoi(id_buf);
		item["amount"] = std::stoi(amount_buf);
		item["currency"] = currency_buf;
		item["channel"] = channel_buf;
		item["status"] = status_buf;
		item["created_at"] = created_buf;
		item["paid_at"] = strlen(paid_buf) > 0 ? paid_buf : nullptr;
		arr.push_back(item);
	}
	sl.unlock();
	res.set_content(arr.dump(), "application/json");
}
