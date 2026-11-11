// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#ifndef TICKET_CONTROLLER_HPP
#define TICKET_CONTROLLER_HPP

#include "http.hpp"

HANDLER_FUNC(ticket_create);
HANDLER_FUNC(ticket_list);
HANDLER_FUNC(ticket_detail);
HANDLER_FUNC(ticket_reply);
HANDLER_FUNC(ticket_close);
HANDLER_FUNC(ticket_orders);

#endif
