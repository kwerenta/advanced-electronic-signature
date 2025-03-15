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
