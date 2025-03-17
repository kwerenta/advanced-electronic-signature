#include <raylib.h>
#include <stdio.h>
#include <string.h>
#include "util.h"

/**
 * @brief Required by Clay library to work properly
 */
#define CLAY_IMPLEMENTATION
#include "clay-shared.h"
#include "lib/clay.h"

const Clay_Color COLOR_LIGHT = {224, 215, 210, 255};
const Clay_Color COLOR_RED = {168, 66, 28, 255};
const Clay_Color COLOR_ORANGE = {225, 138, 50, 255};
const Clay_Color COLOR_BACKGROUND = {72, 84, 96, 255};
const Clay_Color COLOR_BUTTON_BG = {5, 196, 107, 255};
const Clay_Color COLOR_BUTTON_HOVER = {11, 232, 129, 255};


void handleBrowseButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME)
    printf("File browsing placeholder");
}

/**
 * @brief Creates layout for the app when no pendrives containing key files has been found.
 */
void layout_waiting() {
  CLAY({.id = CLAY_ID("Container"),
        .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                  .padding = CLAY_PADDING_ALL(16),
                  .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER},
                  .childGap = 16},
        .backgroundColor = COLOR_BACKGROUND}) {
    CLAY_TEXT(CLAY_STRING("Waiting for the USB drive to be plugged in..."),
              CLAY_TEXT_CONFIG({.fontSize = 26, .textColor = {255, 255, 255, 255}}));
  }
}

/**
 * @brief Creates layout for the app when a key file has been found on a drive.
 * @param key_file Name of the found key file to be displayed
 */
void layout_detected(const char *key_file) {
  uint32_t len = strlen(key_file);

  CLAY({.id = CLAY_ID("Container"),
        .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                  .padding = CLAY_PADDING_ALL(16),
                  .layoutDirection = CLAY_TOP_TO_BOTTOM,
                  .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER},
                  .childGap = 16},
        .backgroundColor = COLOR_BACKGROUND}) {
    CLAY_TEXT(CLAY_STRING("Detected usb drive with the following key:"),
              CLAY_TEXT_CONFIG({.fontSize = 26, .textColor = {255, 255, 255, 255}}));
    CLAY_TEXT(((Clay_String){.chars = key_file, .length = len}),
              CLAY_TEXT_CONFIG({.fontSize = 26, .textColor = {255, 255, 255, 255}}));
    CLAY({.id = CLAY_ID("BrowseButton"),
          .layout = {.padding = {12, 16, 16, 12}},
          .cornerRadius = CLAY_CORNER_RADIUS(4),
          .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_HOVER : COLOR_BUTTON_BG}) {
      Clay_OnHover(handleBrowseButtonInteraction, (intptr_t)0); // TODO - pass real user data here
      CLAY_TEXT(CLAY_STRING("Select PDF file"), CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = {255, 255, 255, 255}}));
    }
  }
}

int main() {
  clay_init("Signature App");

  Font fonts[1];
  fonts[0] = LoadFontEx("../res/OpenSans-Regular.ttf", 48, 0, 400);
  SetTextureFilter(fonts[0].texture, TEXTURE_FILTER_BILINEAR);
  clay_set_measure_text(fonts);

  char key_file[128] = {};

  while (!WindowShouldClose()) {
    clay_handle_movement();

    Clay_BeginLayout();

    if (find_private_key(key_file))
     layout_detected(key_file);
    else
     layout_waiting();

    Clay_RenderCommandArray renderCommands = Clay_EndLayout();

    clay_render(renderCommands, fonts);
  }
}
