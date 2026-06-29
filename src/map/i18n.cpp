#include "i18n.hpp"

#include <fstream>
#include <iterator>
#include <string>
#include <unordered_map>

#include <common/core.hpp>
#include <common/showmsg.hpp>
#include <common/strlib.hpp>
#include <ryml_std.hpp>
#include <ryml.hpp>

static std::unordered_map<int32, std::unordered_map<std::string, std::string>> i18n_storage;

static const char* i18n_langcode(int32 langtype)
{
	switch(langtype){
		case 0:
			return "english";
		case 4:
			return "chinese";
		default:
			return "english";
	}
}

static bool i18n_load_lang(int32 langtype, const char* filename)
{
	std::string path = std::string(db_path) + "/i18n/dialog/" + filename;
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

const char* i18n_translate(int32 langtype, const char* key, const char* fallback)
{
	if(key == nullptr)
		return fallback;

	auto it_lang = i18n_storage.find(langtype);
	if(it_lang == i18n_storage.end())
		return fallback;

	auto it = it_lang->second.find(key);
	if(it == it_lang->second.end())
		return fallback;

	return it->second.c_str();
}

void i18n_init()
{
	i18n_reload();
}

void i18n_reload()
{
	i18n_storage.clear();
	i18n_load_lang(0, "english.yml");
	i18n_load_lang(4, "chinese.yml");
}
