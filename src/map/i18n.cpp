#include "i18n.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <unordered_map>

#include <common/core.hpp>
#include <common/showmsg.hpp>
#include <common/strlib.hpp>
#include <ryml_std.hpp>
#include <ryml.hpp>

#include "battle.hpp"

static std::unordered_map<int32, std::unordered_map<std::string, std::string>> i18n_storage;

static const char* i18n_langcode(int32 langtype)
{
	switch(langtype){
		case 0:
			return "en";
		case 4:
			return "zh";
		default:
			return "en";
	}
}

static bool i18n_parse_file(int32 langtype, const std::string& path)
{
	std::ifstream ifs(path, std::ios::binary);
	if(!ifs){
		ShowWarning("i18n: failed to open %s\n", path.c_str());
		return false;
	}
	std::string buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
	ifs.close();

	ryml::Parser parser;
	ryml::Tree tree;
	try{
		tree = parser.parse_in_arena(c4::to_csubstr(path), c4::to_csubstr(buf));
	}catch(const std::runtime_error& e){
		ShowError("i18n: failed to parse %s: %s\n", path.c_str(), e.what());
		return false;
	}

	const ryml::NodeRef& root = tree.rootref();
	if(!root.has_child(c4::to_csubstr("Body"))){
		ShowWarning("i18n: missing Body in %s\n", path.c_str());
		return false;
	}

	const ryml::NodeRef& body = root["Body"];
	size_t count = 0;
	for(const ryml::NodeRef& node : body){
		if(!node.has_key())
			continue;

		std::string key(node.key().str, node.key().len);
		std::string value;

		if(node.val_is_null()){
			value.clear();
		}else{
			try{
				node >> value;
			}catch(const std::runtime_error& e){
				ShowWarning("i18n: failed to read value for key %s in %s: %s\n", key.c_str(), path.c_str(), e.what());
				continue;
			}
		}

		i18n_storage[langtype][key] = value;
		++count;
	}

	ShowStatus("i18n: loaded %zu entries for language %d from %s\n", count, langtype, path.c_str());
	return true;
}

static void i18n_load_scope(int32 langtype, const char* langcode, const char* scope)
{
	std::string base = std::string(db_path) + "/i18n/dialog/" + langcode + "/" + scope;
	std::filesystem::path dir(base);

	if(!std::filesystem::exists(dir)){
		return;
	}

	std::error_code ec;
	for(auto& entry : std::filesystem::recursive_directory_iterator(dir, ec)){
		if(ec){
			ShowWarning("i18n: directory iteration error in %s: %s\n", base.c_str(), ec.message().c_str());
			break;
		}
		if(!entry.is_regular_file())
			continue;
		if(entry.path().extension() != ".yml")
			continue;

		i18n_parse_file(langtype, entry.path().string());
	}
}

static void i18n_load_legacy(int32 langtype, const char* filename)
{
	std::string path = std::string(db_path) + "/i18n/dialog/" + filename;
	std::error_code ec;
	if(std::filesystem::exists(path, ec)){
		i18n_parse_file(langtype, path);
	}
}

const char* i18n_translate(int32 langtype, const char* key, const char* fallback)
{
	if(key == nullptr)
		return fallback;

	auto it_lang = i18n_storage.find(langtype);
	if(it_lang != i18n_storage.end()){
		auto it = it_lang->second.find(key);
		if(it != it_lang->second.end())
			return it->second.c_str();
	}

	if(battle_config.i18n_debug){
		static char missing_buf[256];
		int n = snprintf(missing_buf, sizeof(missing_buf), "[MISSING:%s]", key);
		if(n < 0)
			return fallback;
		if((size_t)n >= sizeof(missing_buf))
			ShowWarning("i18n: key too long, truncated in [MISSING:] output: %s\n", key);
		return missing_buf;
	}

	return fallback;
}

void i18n_init()
{
	i18n_reload();
}

void i18n_reload()
{
	i18n_storage.clear();

	i18n_load_scope(0, i18n_langcode(0), "custom");
	i18n_load_scope(0, i18n_langcode(0), "override");
	i18n_load_legacy(0, "english.yml");

	i18n_load_scope(4, i18n_langcode(4), "custom");
	i18n_load_scope(4, i18n_langcode(4), "override");
	i18n_load_legacy(4, "chinese.yml");
}
