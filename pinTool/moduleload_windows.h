#pragma once


#include "modules.h"
#include "wrap_ucrtbase.h"
#include "wrap_kernel32.h"
#include "wrap_advapi32.h"
#include "wrap_user32.h"

VOID moduleLoad(IMG img, VOID *v);