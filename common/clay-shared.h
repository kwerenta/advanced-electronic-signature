#ifndef CLAY_SHARED_H
#define CLAY_SHARED_H

#include "lib/clay.h"
#include <raylib.h>

/**
 * @brief Initializes Clay library context
 * @param[in] window_title Title the window will have after creation
 */
void clay_init(const char *window_title);

/**
 * @brief Renders all Clay structures to the window
 * @param render_commands Commands that will be rendered. Returned by Clay_EndLayout function
 * @param[in] fonts Array of loaded fonts
 */
void clay_render(Clay_RenderCommandArray render_commands, Font *fonts);

/**
 * @brief Sets measure text function to properly measure width of text that appears on the screen
 * @param[in] fonts Array of loaded fonts
 */
void clay_set_measure_text(Font *fonts);

/**
 * @brief Handles window resizing, scrolling and mouse movement in order to calculate layout properly
 */
void clay_handle_movement();

#endif
