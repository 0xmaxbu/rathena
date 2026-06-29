#ifndef MAP_I18N_HPP
#define MAP_I18N_HPP

#include <common/cbasetypes.hpp>

const char* i18n_translate(int32 langtype, const char* key, const char* fallback);
void i18n_init();
void i18n_reload();

#endif
