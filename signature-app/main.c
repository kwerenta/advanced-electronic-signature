#include <raylib.h>
#include <stdio.h>

/**
 * @brief Required by Clay library to work properly
 */
#define CLAY_IMPLEMENTATION
#include "clay-shared.h"
#include "lib/clay.h"

const Clay_Color COLOR_LIGHT = {224, 215, 210, 255};
const Clay_Color COLOR_RED = {168, 66, 28, 255};
const Clay_Color COLOR_ORANGE = {225, 138, 50, 255};

int main() {
  clay_init("Signature App");

  Font fonts[1];
  fonts[0] = LoadFontEx("../res/OpenSans-Regular.ttf", 48, 0, 400);
  SetTextureFilter(fonts[0].texture, TEXTURE_FILTER_BILINEAR);
  clay_set_measure_text(fonts);

  while (!WindowShouldClose()) {
    clay_handle_movement();

    Clay_BeginLayout();

    CLAY({.id = CLAY_ID("OuterContainer"),
          .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                     .padding = CLAY_PADDING_ALL(16),
                     .childGap = 16},
          .backgroundColor = {250, 250, 255, 255}}) {
      CLAY({.id = CLAY_ID("SideBar"),
            .layout = {.layoutDirection = CLAY_TOP_TO_BOTTOM,
                       .sizing = {.width = CLAY_SIZING_FIXED(300), .height = CLAY_SIZING_GROW(0)},
                       .padding = CLAY_PADDING_ALL(16),
                       .childGap = 16},
            .backgroundColor = COLOR_LIGHT}) {
        CLAY({.id = CLAY_ID("ProfilePictureOuter"),
              .layout = {.sizing = {.width = CLAY_SIZING_GROW(0)},
                         .padding = CLAY_PADDING_ALL(16),
                         .childGap = 16,
                         .childAlignment = {.y = CLAY_ALIGN_Y_CENTER}},
              .backgroundColor = COLOR_RED}) {
          CLAY_TEXT(CLAY_STRING("Clay - UI Library"),
                    CLAY_TEXT_CONFIG({.fontSize = 24, .textColor = {255, 255, 255, 255}}));
        }

        CLAY({.id = CLAY_ID("MainContent"),
              .layout = {.sizing = {.width = CLAY_SIZING_GROW(0), .height = CLAY_SIZING_GROW(0)}},
              .backgroundColor = COLOR_LIGHT}) {}
      }
    }

    Clay_RenderCommandArray renderCommands = Clay_EndLayout();

    clay_render(renderCommands, fonts);
  }
}
