#pragma once

#include <common/types.h>

int snapshot(bool prepare);

cap_t restore(badge_t badge, unsigned long pcid);
