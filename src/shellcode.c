#include "runtime.h"

void payload_main(SC_ENV *env);

int main(void) {
    SC_ENV env;
    sc_init_env(&env);
    payload_main(&env);
    return 0;
}

#include "runtime.c"
#include "payload_msgbox.c"