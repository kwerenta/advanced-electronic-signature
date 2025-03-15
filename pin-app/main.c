#include "crypto.h"
#include <raylib.h>
#include <stdio.h>
#include <string.h>

/**
 *@brief Maxium length of PIN that user can enter
 */
#define MAX_PIN_LENGTH (16)

/**
 * @brief Required by Clay library to work properly
 */
#define CLAY_IMPLEMENTATION
#include "clay-shared.h"
#include "lib/clay.h"

/**
 * @brief White color
 */
const Clay_Color COLOR_WHITE = {255, 255, 255, 255};
/**
 * @brief Color for button background
 */
const Clay_Color COLOR_BUTTON_BG = {5, 196, 107, 255};
/**
 * @brief Color for button background when it is hovered
 */
const Clay_Color COLOR_BUTTON_HOVER = {11, 232, 129, 255};

Clay_BorderElementConfig get_pin_box_border(uint8_t curr_index, uint8_t index) {
  if (curr_index != index)
    return (Clay_BorderElementConfig){};

  return (Clay_BorderElementConfig){.color = {15, 188, 249, 255}, .width = CLAY_BORDER_ALL(2)};
}

typedef struct {
  uint8_t curr_index;
  char pin[MAX_PIN_LENGTH + 1];
} PinData;

/**
 * @brief Handles PIN input using keyboard
 * @param curr_index Currently selected PIN character
 * @param pin PIN storage
 *
 * @TODO PIN should be able to contain other characters than just digits
 */
void handle_controls(PinData *data) {
  int key = GetKeyPressed();

  if (key >= KEY_ZERO && key <= KEY_NINE) {
    data->pin[data->curr_index] = key;
    if (data->curr_index + 1 < MAX_PIN_LENGTH)
      data->curr_index++;
    return;
  }

  if (key == KEY_BACKSPACE) {
    if (data->curr_index - 1 >= 0 && (data->curr_index < MAX_PIN_LENGTH - 1 ||
                                      (data->curr_index == MAX_PIN_LENGTH - 1 && data->pin[data->curr_index] == 0)))
      data->curr_index--;
    data->pin[data->curr_index] = 0;
    return;
  }
}

/**
 * @brief Detects if button was clicked and tries to generate RSA key pair
 */
void handleCreateButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  PinData *data = (PinData *)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
    if (data->curr_index > 0) {
      generate_encrypted_RSA_keypair(data->pin, "encrypted_private_key.pem", "public_key.pem");
      printf("Created RSA key pair with PIN: %s\n", data->pin);
      return;
    }

    printf("PIN is too short\n");
  }
}

int main() {
  clay_init("Pin App");

  Font fonts[1];
  fonts[0] = LoadFontEx("../res/OpenSans-Regular.ttf", 48, 0, 400);
  SetTextureFilter(fonts[0].texture, TEXTURE_FILTER_BILINEAR);
  clay_set_measure_text(fonts);

  PinData data = {.pin = {}, .curr_index = 0};

  while (!WindowShouldClose()) {
    clay_handle_movement();

    handle_controls(&data);

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

        for (uint8_t i = 0; i < MAX_PIN_LENGTH; i++) {
          CLAY({.id = CLAY_IDI_LOCAL("PinNumber", i),
                .layout = {.sizing = {CLAY_SIZING_FIXED(36), CLAY_SIZING_FIXED(48)},
                           .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER}},
                .cornerRadius = CLAY_CORNER_RADIUS(4),
                .border = get_pin_box_border(data.curr_index, i),
                .backgroundColor = {210, 218, 226, 255}}) {

            if (data.pin[i] != 0) {
              CLAY_TEXT(((Clay_String){.chars = &(data.pin)[i], .length = 1}),
                        CLAY_TEXT_CONFIG({.fontSize = 48, .textColor = {0, 0, 0, 255}}));
            }
          }
        }
      }
      CLAY_TEXT(CLAY_STRING("Enter PIN that will be used to encrypt private key"),
                CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = COLOR_WHITE}));

      CLAY({.id = CLAY_ID("CreateButton"),
            .layout = {.padding = {12, 16, 16, 12}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_HOVER : COLOR_BUTTON_BG}) {
        Clay_OnHover(handleCreateButtonInteraction, (intptr_t)&data);
        CLAY_TEXT(CLAY_STRING("Create RSA key pair"), CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = COLOR_WHITE}));
      }
    }

    Clay_RenderCommandArray renderCommands = Clay_EndLayout();
    clay_render(renderCommands, fonts);
  }
}
