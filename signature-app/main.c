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

const Clay_Color COLOR_LIGHT = {224, 215, 210, 255};
const Clay_Color COLOR_RED = {168, 66, 28, 255};
const Clay_Color COLOR_ORANGE = {225, 138, 50, 255};
const Clay_Color COLOR_BACKGROUND = {72, 84, 96, 255};
const Clay_Color COLOR_BUTTON_BG = {5, 196, 107, 255};
const Clay_Color COLOR_BUTTON_HOVER = {11, 232, 129, 255};

typedef enum {
  MODE_INITIAL,
  MODE_SIGN,
  MODE_VERIFY
} AppMode;

typedef struct {
  AppMode mode;
  char key_file[128];
  char pdf_file[128];
} Context;

void handleChoiceSignInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;
  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME)
    ctx->mode = MODE_SIGN;
}

void handleChoiceVerifyInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;
  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME)
    ctx->mode = MODE_VERIFY;
}


void handleBrowsePdfButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
    nfdchar_t *path = NULL;
    nfdresult_t res = NFD_OpenDialog("pdf", NULL, &path);

    if (res == NFD_OKAY)
      strncpy(ctx->pdf_file, path, 128);

    free(path);
  }
}

void handleBrowsePubKeyButtonInteraction(Clay_ElementId id, Clay_PointerData pointer_info, intptr_t user_data) {
  Context *ctx = (Context*)user_data;

  if (pointer_info.state == CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
    nfdchar_t *path = NULL;
    nfdresult_t res = NFD_OpenDialog("pub", NULL, &path);

    if (res == NFD_OKAY)
      strncpy(ctx->key_file, path, 128);

    free(path);
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
    CLAY({.id = CLAY_ID("BrowseButton"),
          .layout = {.padding = {12, 16, 16, 12}},
          .cornerRadius = CLAY_CORNER_RADIUS(4),
          .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_HOVER : COLOR_BUTTON_BG},) {
      Clay_OnHover(handleBrowsePdfButtonInteraction, (intptr_t)ctx);
      CLAY_TEXT(CLAY_STRING("Select PDF file"), CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = {255, 255, 255, 255}}));
    }
    CLAY({.id = CLAY_ID("ChoiceSignButton"),
          .layout = {.padding = {12, 16, 16, 12}},
          .cornerRadius = CLAY_CORNER_RADIUS(4),
          .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_HOVER : COLOR_BUTTON_BG}) {
      Clay_OnHover(handleChoiceSignInteraction, (intptr_t)ctx);
      CLAY_TEXT(CLAY_STRING("Sign"), CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = {255, 255, 255, 255}}));
    }
    CLAY({.id = CLAY_ID("ChoiceVerifyButton"),
          .layout = {.padding = {12, 16, 16, 12}},
          .cornerRadius = CLAY_CORNER_RADIUS(4),
          .backgroundColor = Clay_Hovered() ? COLOR_BUTTON_HOVER : COLOR_BUTTON_BG}) {
      Clay_OnHover(handleChoiceVerifyInteraction, (intptr_t)ctx);
      CLAY_TEXT(CLAY_STRING("Verify"), CLAY_TEXT_CONFIG({.fontSize = 36, .textColor = {255, 255, 255, 255}}));
    }
  }
}


/**
 * @brief Creates a layout for the app when it's in sign mode
 * @param ctx Pointer to the application's context
 */
void layout_sign(Context *ctx) {
  uint32_t len = strlen(ctx->key_file);

  CLAY({.id = CLAY_ID("Container"),
        .layout = {.sizing = {CLAY_SIZING_GROW(0), CLAY_SIZING_GROW(0)},
                  .padding = CLAY_PADDING_ALL(16),
                  .layoutDirection = CLAY_TOP_TO_BOTTOM,
                  .childAlignment = {.x = CLAY_ALIGN_X_CENTER, .y = CLAY_ALIGN_Y_CENTER},
                  .childGap = 16},
        .backgroundColor = COLOR_BACKGROUND}) {

    if (find_private_key(ctx->key_file) == 0) {
      CLAY_TEXT(CLAY_STRING("Waiting for pendrive to be plugged in ..."),
                CLAY_TEXT_CONFIG({.fontSize = 26, .textColor = {255, 255, 255, 255}}));
    }
    else {
      CLAY_TEXT(CLAY_STRING("Detected usb drive with the following key:"),
                CLAY_TEXT_CONFIG({.fontSize = 26, .textColor = {255, 255, 255, 255}}));
      CLAY_TEXT(((Clay_String){.chars = ctx->key_file, .length = len}),
                CLAY_TEXT_CONFIG({.fontSize = 26, .textColor = {255, 255, 255, 255}}));
    }
  }
}

/**
 * @brief Creates a layout for the app when it's in verify mode
 * @param ctx Pointer to the application's context
 */
void layout_verify(Context *ctx) {

}

int main() {
  clay_init("Signature App");

  Font fonts[1];
  fonts[0] = LoadFontEx("../res/OpenSans-Regular.ttf", 48, 0, 400);
  SetTextureFilter(fonts[0].texture, TEXTURE_FILTER_BILINEAR);
  clay_set_measure_text(fonts);

  Context ctx = {.mode = MODE_INITIAL, .key_file = {}, .pdf_file = {}};

  while (!WindowShouldClose()) {
    clay_handle_movement();

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
