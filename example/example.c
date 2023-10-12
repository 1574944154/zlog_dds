#include <stdio.h>
#include <stdint.h>
#include <zlog.h>



int main(int argc, char *argv[])
{
    int rc;

    zlog_category_t *c = NULL;

    // zlog_config_add_format("simple", "%d %c %m%n");

    // add_format_property("normal", "%d(%F %T.%l) %c %m%n");

    // zlog_config_add_rule("*", "*", "stdout", 10*1024*1024, 10, "", "simple");

    // // add_rule_property("discovery", "*", "%c.log", 10, 1024*1024, "%c.#r.log", "normal");
    // add_rule_property("discovery", "*", "%c.log", 10*1024*1024, 10, "%c.#r.log", "normal");

    // zlog_config_init(1024, 10*1024*1024, "/tmp/zlog.lock", "%d(%F %T.%l) %c %-6V (%c:%F:%L) - %m%n", 0600, 0);

    // rc = dzlog_init("dds");
    // if (rc) {
    //     printf("init failed\n");
    //     return -1;
    // }

    // rc = zlog_init();
    // rc = zlog_init();
    rc = dzlog_init ("dds", "stdout", 10*1024*1024, 10);

    c = zlog_get_category("discovery");
    if (!c) {
        printf("not found category\n");
        return -1;
    }

    // for(int i=0;i<1e6;i++) {
        zlog_info(c, "hello, zlog -----------------------------------------");
        // zlog_info(c, "hello, zlog -----------------------------------------");
        // zlog_info(c, "hello, zlog -----------------------------------------");
    // }

    // dzlog_info ("this is info");


    // zlog_fini();

    return 0;
}
