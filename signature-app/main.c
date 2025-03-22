#include <raylib.h>
#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "util.h"
#include "nfd.h"
/**
 * @brief Required by Clay library to work properly
 */
#define CLAY_IMPLEMENTATION
#include "clay-shared.h"
#include "lib/clay.h"

#define MAX_PIN_LENGTH (16)

#define DEFAULT_TEXT_CONFIG {.fontSize = 26, .textColor = {255, 255, 255, 255}}
#define BUTTON_TEXT_CONFIG {.fontSize = 36, .textColor = {255, 255, 255, 255}}

const Clay_Color COLOR_LIGHT = {224, 215, 210, 255};
const Clay_Color COLOR_RED = {168, 66, 28, 255};
const Clay_Color COLOR_ORANGE = {225, 138, 50, 255};
const Clay_Color COLOR_BACKGROUND = {72, 84, 96, 255};

const Clay_Color COLOR_BUTTON_CANCEL_BG = {218, 44, 56, 255};
const Clay_Color COLOR_BUTTON_CANCEL_HOVER = {224, 82, 91, 255};
const Clay_Color COLOR_BUTTON_PROCEED_BG = {5, 196, 107, 255};
const Clay_Color COLOR_BUTTON_PROCEED_HOVER = {11, 232, 129, 255};
const Clay_Color COLOR_BUTTON_CHANGE_BG = {120, 120, 120, 255};
const Clay_Color COLOR_BUTTON_CHANGE_HOVER = {150, 150, 150, 255};

typedef enum {
  MODE_INITIAL,
  MODE_SIGN,
  MODE_VERIFY
} AppMode;

typedef struct {
  uint8_t curr_index;
  char pin[MAX_PIN_LENGTH + 1];
} PinData;

typedef struct {
  AppMode mode;
  PinData pin_data;
  char sign_key_file[128];
  char verify_key_file[128];
  char pdf_file[128];
} Context;

Clay_BorderElementConfig get_pin_box_border(uint8_t curr_index, uint8_t index) {
  if (curr_index != index)
    return (Clay_BorderElementConfig){};

  return (Clay_BorderElementConfig){.color = {15, 188, 249, 255}, .width = CLAY_BORDER_ALL(2)};
}

/**
 * @brief Handles PIN input using keyboard
 * @param ctx Application context
 */
 void handle_controls(Context *ctx) {

  if (ctx->mode != MODE_SIGN || ctx->sign_key_file[0] == 0)
    return;

  int key = GetCharPressed();
  while (key > 0) {
    // NOTE: Only allow ASCII printable characters
    if (key >= 32 && key <= 126) {
      ctx->pin_data.pin[ctx->pin_data.curr_index] = key;
      if (ctx->pin_data.curr_index + 1 < MAX_PIN_LENGTH)
        ctx->pin_data.curr_index++;
      return;
    }

    key = GetCharPressed();
  }

  if (IsKeyPressed(KEY_BACKSPACE) || IsKeyPressedRepeat(KEY_BACKSPACE)) {
    if (ctx->pin_data.curr_index - 1 >= 0 && (ctx->pin_data.curr_index < MAX_PIN_LENGTH - 1 ||
        (ctx->pin_data.curr_index == MAX_PIN_LENGTH - 1 && ctx->pin_data.pin[ctx->pin_data.curr_index] == 0)))
      ctx->pin_data.curr_index--;
    ctx->pin_data.pin[ctx->pin_data.curr_index] = 0;
    return;
  }
}

/**
 * @brief Detects if button was clicked and changes the application mode
 */
void handleChoiceSignInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;
  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME)
    ctx->mode = MODE_SIGN;
}

/**
 * @brief Detects if button was clicked and changes the application mode
 */
void handleChoiceVerifyInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;
  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME)
    ctx->mode = MODE_VERIFY;
}

/**
 * @brief Detects if button was clicked and changes the application mode
 */
void handleCancelButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME)
    ctx->mode = MODE_INITIAL;
}

/**
 * @brief Detects if button was clicked and opens file dialog with '.pdf' filter
 */
void handleBrowsePdfButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
    nfdchar_t *path = NULL;
    nfdresult_t res = NFD_OpenDialog("pdf", NULL, &path);

    if (res == NFD_OKAY) {
      if (ctx->pdf_file[0] != 0) memset(ctx->pdf_file, 0, 128);
      strncpy(ctx->pdf_file, path, 128);
    }

    free(path);
  }
}

/**
 * @brief Detects if button was clicked and opens file dialog with '.pub' filter
 */
void handleBrowsePubKeyButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
    nfdchar_t *path = NULL;
    nfdresult_t res = NFD_OpenDialog("pub", NULL, &path);

    if (res == NFD_OKAY) {
      if (ctx->verify_key_file[0] != 0) memset(ctx->verify_key_file, 0, 128);
      strncpy(ctx->verify_key_file, path, 128);
    }

    free(path);
  }
}

/**
 * @brief Detects if button was clicked and tries to sign the chosen file
 */
void handleConfirmSignButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
    printf("Document signing placeholder\n");
  }
}

/**
 * @brief Detects if button was clicked and tries to verify the chosen file
 */
void handleConfirmVerifyButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
    printf("Document verification placeholder\n");
  }
}

/**
 * @brief Creates a layout for the app's initial view
 * @param ctx Pointer to the application's context
 */
void layout_initial(Context *ctx) {
  CLAY({.id = CLAY_ID("Container"),
        .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                   .padding = CLAY_PADDING_ALL(16),
                   .layoutDirection = CLAY_TOP_TO_BOTTOM,
                   .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER},
                   .childGap = 16},
        .backgroundColor = COLOR_BACKGROUND}) {
    if (ctx->pdf_file[0] == 0) {
      CLAY({.id = CLAY_ID("BrowsePdfButton"),
            .layout = {.padding = {12, 16, 16, 12},
                       .sizing = {CLAY_SIZING_PERCENT(0.25)},
                       .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_PROCEED_HOVER : COLOR_BUTTON_PROCEED_BG}) {
        Clay_OnHover(handleBrowsePdfButtonInteraction, (intptr_t)ctx);
        CLAY_TEXT(CLAY_STRING("Select PDF file"), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
      }
    }
    else {
      uint32_t len = strlen(ctx->pdf_file);

      CLAY_TEXT(CLAY_STRING("Selected PDF file:"), CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

      CLAY_TEXT(((Clay_String){.chars = ctx->pdf_file, .length = len}), CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

      CLAY({.id = CLAY_ID("ChangePdfButton"),
            .layout = {.padding = {12, 16, 16, 12},
                       .sizing = {CLAY_SIZING_PERCENT(0.25)},
                       .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_CHANGE_HOVER : COLOR_BUTTON_CHANGE_BG}) {
        Clay_OnHover(handleBrowsePdfButtonInteraction, (intptr_t)ctx);
        CLAY_TEXT(CLAY_STRING("Change file"), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
      }

      CLAY({.id = CLAY_ID("ChoiceSignButton"),
            .layout = {.padding = {12, 16, 16, 12},
                       .sizing = {CLAY_SIZING_PERCENT(0.25)},
                       .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_PROCEED_HOVER : COLOR_BUTTON_PROCEED_BG}) {
        Clay_OnHover(handleChoiceSignInteraction, (intptr_t)ctx);
        CLAY_TEXT(CLAY_STRING(" Sign "), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
      }

      CLAY({.id = CLAY_ID("ChoiceVerifyButton"),
            .layout = {.padding = {12, 16, 16, 12},
                       .sizing = {CLAY_SIZING_PERCENT(0.25)},
                       .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_PROCEED_HOVER : COLOR_BUTTON_PROCEED_BG}) {
        Clay_OnHover(handleChoiceVerifyInteraction, (intptr_t)ctx);
        CLAY_TEXT(CLAY_STRING("Verify"), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
      }
    } 
  }
}

/**
 * @brief Creates a layout for the app when it's in sign mode
 * @param ctx Pointer to the application's context
 */
void layout_sign(Context *ctx) {
  CLAY({.id = CLAY_ID("Container"),
        .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                   .padding = CLAY_PADDING_ALL(16),
                   .layoutDirection = CLAY_TOP_TO_BOTTOM,
                   .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER},
                   .childGap = 16},
        .backgroundColor = COLOR_BACKGROUND}) {
    uint32_t pdf_len = strlen(ctx->pdf_file);

    CLAY_TEXT(CLAY_STRING("Selected PDF file:"), CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

    CLAY_TEXT(((Clay_String){.chars = ctx->pdf_file, .length = pdf_len}), CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

    if (find_private_key(ctx->sign_key_file) == 0) {
      CLAY_TEXT(CLAY_STRING("Waiting for pendrive to be plugged in ..."),
                CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));
    }
    else {
      uint32_t key_len = strlen(ctx->sign_key_file);

      CLAY_TEXT(CLAY_STRING("Detected key:"), CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

      CLAY_TEXT(((Clay_String){.chars = ctx->sign_key_file, .length = key_len}),
                CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

      CLAY_TEXT(CLAY_STRING("Enter PIN:"), CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

      CLAY({.id = CLAY_ID("PinContainer"),
            .layout = {.padding = CLAY_PADDING_ALL(8), .childGap = 8},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = {30, 39, 46, 255}}) {

        for (uint8_t i = 0; i < MAX_PIN_LENGTH; i++) {
          CLAY({.id = CLAY_IDI_LOCAL("PinNumber", i),
                .layout = {.sizing = {CLAY_SIZING_FIXED(36), CLAY_SIZING_FIXED(48)},
                            .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER}},
                .cornerRadius = CLAY_CORNER_RADIUS(4),
                .border = get_pin_box_border(ctx->pin_data.curr_index, i),
                .backgroundColor = {210, 218, 226, 255}}) {

            if (ctx->pin_data.pin[i] != 0) {
              CLAY_TEXT(((Clay_String){.chars = &(ctx->pin_data.pin)[i], .length = 1}),
                        CLAY_TEXT_CONFIG({.fontSize = 48, .textColor = {0, 0, 0, 255}}));
            }
          }
        }
      }

      CLAY({.id = CLAY_ID("ConfirmSignButton"),
            .layout = {.padding = {12, 16, 16, 12},
                       .sizing = {CLAY_SIZING_PERCENT(0.25)},
                       .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_PROCEED_HOVER : COLOR_BUTTON_PROCEED_BG}) {
        Clay_OnHover(handleChoiceVerifyInteraction, (intptr_t)ctx);
        CLAY_TEXT(CLAY_STRING("Confirm sign"), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
      }
    }

    CLAY({.id = CLAY_ID("SignCancelButton"),
          .layout = {.padding = {12, 16, 16, 12},
                     .sizing = {CLAY_SIZING_PERCENT(0.25)},
                     .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
          .cornerRadius = CLAY_CORNER_RADIUS(4),
          .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_CANCEL_HOVER : COLOR_BUTTON_CANCEL_BG}) {
      Clay_OnHover(handleCancelButtonInteraction, (intptr_t)ctx);
      CLAY_TEXT(CLAY_STRING("Cancel"), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
    }
  }
}

/**
 * @brief Creates a layout for the app when it's in verify mode
 * @param ctx Pointer to the application's context
 */
void layout_verify(Context *ctx) {
  CLAY({.id = CLAY_ID("Container"),
        .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                   .padding = CLAY_PADDING_ALL(16),
                   .layoutDirection = CLAY_TOP_TO_BOTTOM,
                   .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER},
                   .childGap = 16},
        .backgroundColor = COLOR_BACKGROUND}) {
    uint32_t pdf_len = strlen(ctx->pdf_file);

    CLAY_TEXT(CLAY_STRING("Selected PDF file:"), CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

    CLAY_TEXT(((Clay_String){.chars = ctx->pdf_file, .length = pdf_len}), CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));
    if (ctx->verify_key_file[0] == 0) {
      CLAY({.id = CLAY_ID("BrowsePubKeyButton"),
            .layout = {.padding = {12, 16, 16, 12},
                      .sizing = {CLAY_SIZING_PERCENT(0.25)},
                      .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_PROCEED_HOVER : COLOR_BUTTON_PROCEED_BG}) {
        Clay_OnHover(handleBrowsePubKeyButtonInteraction, (intptr_t)ctx);
        CLAY_TEXT(CLAY_STRING("Select public key"), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
      }
    }
    else {
      uint32_t key_len = strlen(ctx->verify_key_file);

      CLAY_TEXT(CLAY_STRING("Selected public key:"),
                CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

      CLAY_TEXT(((Clay_String){.chars = ctx->verify_key_file, .length = key_len}),
                CLAY_TEXT_CONFIG(DEFAULT_TEXT_CONFIG));

      CLAY({.id = CLAY_ID("ConfirmVerifyButton"),
            .layout = {.padding = {12, 16, 16, 12},
                        .sizing = {CLAY_SIZING_PERCENT(0.25)},
                        .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
            .cornerRadius = CLAY_CORNER_RADIUS(4),
            .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_PROCEED_HOVER : COLOR_BUTTON_PROCEED_BG}) {
        Clay_OnHover(handleConfirmVerifyButtonInteraction, (intptr_t)ctx);
        CLAY_TEXT(CLAY_STRING("Confirm verify"), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
      }
    }

    CLAY({.id = CLAY_ID("VerifyCancelButton"),
          .layout = {.padding = {12, 16, 16, 12},
                    .sizing = {CLAY_SIZING_PERCENT(0.25)},
                    .childAlignment = {.x = CLAY_ALIGN_X_CENTER}},
          .cornerRadius = CLAY_CORNER_RADIUS(4),
          .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_CANCEL_HOVER : COLOR_BUTTON_CANCEL_BG}) {
      Clay_OnHover(handleCancelButtonInteraction, (intptr_t)ctx);
      CLAY_TEXT(CLAY_STRING("Cancel"), CLAY_TEXT_CONFIG(BUTTON_TEXT_CONFIG));
    }
  }
}

int main() {
  clay_init("Signature App");

  Font fonts[1];
  fonts[0] = LoadFontEx("../res/OpenSans-Regular.ttf", 48, 0, 400);
  SetTextureFilter(fonts[0].texture, TEXTURE_FILTER_BILINEAR);
  clay_set_measure_text(fonts);

  Context ctx = {.mode = MODE_INITIAL, .sign_key_file = {}, .verify_key_file = {}, .pdf_file = {}};

  while (!WindowShouldClose()) {
    clay_handle_movement();

    handle_controls(&ctx);

    Clay_BeginLayout();

    switch (ctx.mode) {
    case MODE_INITIAL: layout_initial(&ctx); break;
    case MODE_SIGN: layout_sign(&ctx); break;
    case MODE_VERIFY: layout_verify(&ctx); break;
    }

    Clay_RenderCommandArray renderCommands = Clay_EndLayout();

    clay_render(renderCommands, fonts);
  }
}
