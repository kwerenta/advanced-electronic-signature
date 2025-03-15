#ifndef CLAY_SHARED_H
#define CLAY_SHARED_H

#include "lib/clay.h"
#include <raylib.h>

void clay_init(const char *window_title);
void clay_render(Clay_RenderCommandArray render_commands, Font *fonts);

void clay_set_measure_text(Font *fonts);

#endif
