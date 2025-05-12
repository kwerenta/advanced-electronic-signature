#include "crypto.h"
#include <raylib.h>
#include <threads.h>

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
/**
 * @brief Color for button background when it is disabled
 */
const Clay_Color COLOR_BUTTON_DISABLED = {33, 33, 33, 255};
/**
 * @brief Color for success state
 */
const Clay_Color COLOR_SUCCESS = {11, 232, 129, 255};
/**
 * @brief Color for warning state
 */
const Clay_Color COLOR_WARNING = {225, 138, 50, 255};

/**
 * @brief Bool indicating wheter key pair is currently being generated
 */
bool isGenerating = false;
/**
 * @brief Bool indicating wheter key pair has already been generated
 */
bool hasGenerated = false;
/**
 * @brief Bool indicating wheter PIN is too short
 */
bool isTooShort = false;

/**
 * @brief Handles PIN input using keyboard
 * @param curr_index Currently selected PIN character
 * @param pin PIN storage
 */
void handle_controls(PinData *data) {
  if (isGenerating)
    return;

  int key = GetCharPressed();
  while (key > 0) {
    isTooShort = true;
    // NOTE: Only allow ASCII printable characters
    if (key >= 32 && key <= 126) {
      data->pin[data->curr_index] = key;
      if (data->curr_index + 1 < MAX_PIN_LENGTH)
        data->curr_index++;
      return;
    }

    key = GetCharPressed();
  }

  if (IsKeyPressed(KEY_BACKSPACE) || IsKeyPressedRepeat(KEY_BACKSPACE)) {
    if (data->curr_index - 1 >= 0 && (data->curr_index < MAX_PIN_LENGTH - 1 ||
                                      (data->curr_index == MAX_PIN_LENGTH - 1 && data->pin[data->curr_index] == 0)))
      data->curr_index--;
    data->pin[data->curr_index] = 0;
    return;
  }
}

int generate_key(void *data_ptr) {
  isGenerating = true;

  PinData *data = (PinData *)data_ptr;
  generate_encrypted_RSA_keypair(data->pin, "encrypted_private_key.key", "public_key.pub");

  isGenerating = false;
  hasGenerated = true;
  return 0;
}

/**
 * @brief Detects if button was clicked and tries to generate RSA key pair
 */
void handleCreateButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  PinData *data = (PinData *)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
    if (isGenerating) {
      return;
    }

    hasGenerated = false;

    if (data->curr_index == 0) {
      isTooShort = true;
      return;
    }

    thrd_t thread;
    thrd_create(&thread, generate_key, data);
    thrd_detach(thread);
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

      clay_layout_pin(&data);

      CLAY_TEXT(CLAY_STRING("Enter PIN that will be used to encrypt private key"),
                CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = COLOR_WHITE}));

      CLAY({.id = CLAY_ID("CreateButton"),
            .layout = {.padding = {12, 16, 16, 12}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = isGenerating     ? COLOR_BUTTON_DISABLED
                               : Clay_Hovered() ? COLOR_BUTTON_HOVER
                                                : COLOR_BUTTON_BG}) {
        Clay_OnHover(handleCreateButtonInteraction, (intptr_t)&data);
        CLAY_TEXT(CLAY_STRING("Generate RSA key pair"), CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = COLOR_WHITE}));
      }

      if (isGenerating)
        CLAY_TEXT(CLAY_STRING("Generating keys..."), CLAY_TEXT_CONFIG({.fontSize = 32, .textColor = COLOR_WHITE}));
      else if (hasGenerated)
        CLAY_TEXT(CLAY_STRING("Successfully generated RSA key pair!"),
                  CLAY_TEXT_CONFIG({.fontSize = 32, .textColor = COLOR_SUCCESS}));
      else if (isTooShort)
        CLAY_TEXT(CLAY_STRING("PIN is too short"), CLAY_TEXT_CONFIG({.fontSize = 32, .textColor = COLOR_WARNING}));
      else
        CLAY_TEXT(CLAY_STRING(" "), CLAY_TEXT_CONFIG({.fontSize = 32}));
    }

    Clay_RenderCommandArray renderCommands = Clay_EndLayout();
    clay_render(renderCommands, fonts);
  }
}
