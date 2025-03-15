#include <raylib.h>
#include <stdio.h>

#define CLAY_IMPLEMENTATION
#include "lib/clay.h"
#include "clay-shared.h"

const Clay_Color COLOR_LIGHT = {224, 215, 210, 255};
const Clay_Color COLOR_RED = {168, 66, 28, 255};
const Clay_Color COLOR_ORANGE = {225, 138, 50, 255};

int main() {
  clay_init("Pin App");

  Font fonts[1];
  fonts[0] = LoadFontEx("../res/OpenSans-Regular.ttf", 48, 0, 400);
  SetTextureFilter(fonts[0].texture, TEXTURE_FILTER_BILINEAR);
  clay_set_measure_text(fonts);

  while (!WindowShouldClose()) {
    Clay_SetLayoutDimensions((Clay_Dimensions){.width = GetScreenWidth(), .height = GetScreenHeight()});

    Vector2 mousePosition = GetMousePosition();
    Clay_SetPointerState((Clay_Vector2){mousePosition.x, mousePosition.y}, IsMouseButtonDown(0));

    Vector2 scrollDelta = GetMouseWheelMoveV();
    Clay_UpdateScrollContainers(true, (Clay_Vector2){scrollDelta.x, scrollDelta.y}, GetFrameTime());

    Clay_BeginLayout();

    CLAY({.id = CLAY_ID("OuterContainer"),
          .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                     .padding = CLAY_PADDING_ALL(16),
                     .childGap = 16},
          .backgroundColor = {250, 250, 255, 255}}) {
      CLAY_TEXT(CLAY_STRING("Pin App"), CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = {0, 0, 0, 255}}));
    }

    Clay_RenderCommandArray renderCommands = Clay_EndLayout();
    clay_render(renderCommands, fonts);
  }
}
