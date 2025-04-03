#include "clay-shared.h"

#include "lib/clay-renderer.c"

#include <raylib.h>
#include <stdint.h>

/**
 * @brief Callback that determines how Clay errors are handled
 * @param errorData Data about error that occured. Passed by Clay library
 */
void HandleClayErrors(Clay_ErrorData errorData) { printf("CLAY ERROR: %s", errorData.errorText.chars); }

void clay_init(const char *window_title) {
  Clay_Raylib_Initialize(1280, 720, window_title, FLAG_WINDOW_RESIZABLE);

  uint64_t totalMemorySize = Clay_MinMemorySize();
  Clay_Arena arena = Clay_CreateArenaWithCapacityAndMemory(totalMemorySize, malloc(totalMemorySize));
  Clay_Initialize(arena, (Clay_Dimensions){.width = GetScreenWidth(), .height = GetScreenHeight()},
                  (Clay_ErrorHandler){HandleClayErrors});
}

void clay_render(Clay_RenderCommandArray renderCommands, Font *fonts) {
  BeginDrawing();
  ClearBackground(BLACK);
  Clay_Raylib_Render(renderCommands, fonts);
  EndDrawing();
}

void clay_set_measure_text(Font *fonts) { Clay_SetMeasureTextFunction(Raylib_MeasureText, fonts); }

void clay_handle_movement() {
  Clay_SetLayoutDimensions((Clay_Dimensions){.width = GetScreenWidth(), .height = GetScreenHeight()});

  Vector2 mousePosition = GetMousePosition();
  Clay_SetPointerState((Clay_Vector2){mousePosition.x, mousePosition.y}, IsMouseButtonDown(0));

  Vector2 scrollDelta = GetMouseWheelMoveV();
  Clay_UpdateScrollContainers(true, (Clay_Vector2){scrollDelta.x, scrollDelta.y}, GetFrameTime());
}

Clay_BorderElementConfig get_pin_box_border(uint8_t curr_index, uint8_t index) {
  if (curr_index != index)
    return (Clay_BorderElementConfig){};

  return (Clay_BorderElementConfig){.color = {15, 188, 249, 255}, .width = CLAY_BORDER_ALL(2)};
}

void clay_layout_pin(PinData *data) {
  CLAY({.id = CLAY_ID("PinContainer"),
        .layout = {.padding = CLAY_PADDING_ALL(8), .childGap = 8},
        .cornerRadius = CLAY_CORNER_RADIUS(4),
        .backgroundColor = {30, 39, 46, 255}}) {

    for (uint8_t i = 0; i < MAX_PIN_LENGTH; i++) {
      CLAY({.id = CLAY_IDI_LOCAL("PinNumber", i),
            .layout = {.sizing = {CLAY_SIZING_FIXED(36), CLAY_SIZING_FIXED(48)},
                        .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .border = get_pin_box_border(data->curr_index, i),
            .backgroundColor = {210, 218, 226, 255}}) {

        if (data->pin[i] != 0) {
          CLAY_TEXT(((Clay_String){.chars = &(data->pin)[i], .length = 1}),
                    CLAY_TEXT_CONFIG({.fontSize = 48, .textColor = {0, 0, 0, 255}}));
        }
      }
    }
  }
}
