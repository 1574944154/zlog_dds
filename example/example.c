#include <stdio.h>
#include <stdint.h>
#include <zlog.h>



int main(int argc, char *argv[])
{
    int rc;

    // zlog_category_t *c = NULL;

    add_format_property("simple", "%d %c %m%n");

    add_format_property("normal", "%d(%F %T.%l) %c %m%n");

    add_rule_property("*", "*", ">stdout", 10*1024*1024, 10, "", "simple");

    // add_rule_property("discovery", "*", "%c.log", 10, 1024*1024, "%c.#r.log", "normal");
    add_rule_property("discovery", "*", "%c.log", 10*1024*1024, 10, "%c.#r.log", "normal");

    zlog_config_init(1024, 10*1024*1024, "/tmp/zlog.lock", "%d(%F %T.%l) %c %-6V (%c:%F:%L) - %m%n", 0600, 0);

    rc = zlog_init();
    if (rc) {
        printf("init failed\n");
        return -1;
    }

    // c = zlog_get_category("discovery");
    // if (!c) {
    //     printf("not found category\n");
    //     return -1;
    // }

    // for(int i=0;i<1e6;i++) {
        zlog_info(DDS_LOGC_DISCOVERY, "hello, zlog -----------------------------------------");
        zlog_info(DDS_LOGC_RADMIN, "hello, zlog -----------------------------------------");
        // zlog_info(c, "hello, zlog -----------------------------------------");
    // }


    zlog_fini();

    return 0;
}
