#include "crypto.h"
#include <raylib.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Required by Clay library to work properly
 */
#define CLAY_IMPLEMENTATION
#include "clay-shared.h"
#include "lib/clay.h"

Clay_BorderElementConfig get_pin_box_border(uint8_t curr_index, uint8_t index) {
  if (curr_index != index)
    return (Clay_BorderElementConfig){};

  return (Clay_BorderElementConfig){.color = {15, 188, 249, 255}, .width = CLAY_BORDER_ALL(2)};
}

/**
 * @brief Handles PIN input using keyboard
 * @param curr_index Currently selected PIN character
 * @param pin PIN storage
 *
 * @TODO PIN should be able to contain other characters than just digits
 */
void handle_controls(uint8_t *curr_index, char pin[16]) {
  int key = GetKeyPressed();

  if (key >= KEY_ZERO && key <= KEY_NINE) {
    pin[*curr_index] = key;
    if (*curr_index + 1 < 16)
      (*curr_index)++;
    return;
  }

  if (key == KEY_BACKSPACE) {
    if (*curr_index - 1 >= 0)
      (*curr_index)--;
    pin[*curr_index] = 0;
    return;
  }

  if (key == KEY_ENTER && *curr_index > 0) {
    generate_encrypted_RSA_keypair(pin, "encrypted_private_key.pem", "public_key.pem");
    printf("Created RSA key pair with PIN: %s\n", pin);
  }
}

int main() {
  clay_init("Pin App");

  Font fonts[1];
  fonts[0] = LoadFontEx("../res/OpenSans-Regular.ttf", 48, 0, 400);
  SetTextureFilter(fonts[0].texture, TEXTURE_FILTER_BILINEAR);
  clay_set_measure_text(fonts);

  char pin[16] = {};
  uint8_t curr_pin_idx = 0;

  while (!WindowShouldClose()) {
    clay_handle_movement();

    handle_controls(&curr_pin_idx, pin);

    Clay_BeginLayout();

    CLAY({.id = CLAY_ID("Container"),
          .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                     .padding = CLAY_PADDING_ALL(16),
                     .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER},
                     .childGap = 16,
                     .layoutDirection = CLAY_TOP_TO_BOTTOM},
          .backgroundColor = {72, 84, 96, 255}}) {

      CLAY({.id = CLAY_ID("PinContainer"),
            .layout = {.padding = CLAY_PADDING_ALL(8), .childGap = 8},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = {30, 39, 46, 255}}) {

        for (uint8_t i = 0; i < 16; i++) {
          CLAY({.id = CLAY_IDI_LOCAL("PinNumber", i),
                .layout = {.sizing = {CLAY_SIZING_FIXED(36), CLAY_SIZING_FIXED(48)},
                           .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER}},
                .cornerRadius = CLAY_CORNER_RADIUS(4),
                .border = get_pin_box_border(curr_pin_idx, i),
                .backgroundColor = {210, 218, 226, 255}}) {

            if (pin[i] != 0) {
              CLAY_TEXT(((Clay_String){.chars = &pin[i], .length = 1}),
                        CLAY_TEXT_CONFIG({.fontSize = 48, .textColor = {0, 0, 0, 255}}));
            }
          }
        }
      }
      CLAY_TEXT(CLAY_STRING("Enter PIN that will be used to encrypt private key"),
                CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = {255, 255, 255, 255}}));
      CLAY_TEXT(CLAY_STRING("Press enter to create encrypted private key"),
                CLAY_TEXT_CONFIG({.fontSize = 28, .textColor = {255, 255, 255, 255}}));
    }

    Clay_RenderCommandArray renderCommands = Clay_EndLayout();
    clay_render(renderCommands, fonts);
  }
}
