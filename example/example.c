#include <stdio.h>
#include <stdint.h>
#include <zlog.h>



void add_format_property(struct log_format_properties_listelem **list, struct log_format_properties_listelem *node)
{
    struct log_format_properties_listelem *node2 = malloc(sizeof(struct log_format_properties_listelem));
    node2->name = node->name;
    node2->pattern = node->pattern;
    node2->next = *list;
    *list = node2;
}

void add_rule_property(struct log_rule_properties_listelem **list, struct log_rule_properties_listelem *node)
{
    struct log_rule_properties_listelem *node2 = malloc(sizeof(struct log_rule_properties_listelem));
    node2->category = node->category;
    node2->level = node->level;
    node2->filePath = node->filePath;
    node2->archiveMaxSize = node->archiveMaxSize;
    node2->archiveMaxCount = node->archiveMaxCount;
    node2->archivePattern = node->archivePattern;
    node2->formatName = node->formatName;
    node2->next = *list;
    *list = node2;
}

struct ddsi_config_logcfg logcfg = {
    .fileSize = 1024,
    .bufferMin = 1024,
    .bufferMax = 10 * 1024 * 1024,
    .rotateLockFile = "/tmp/zlog.lock",
    .defaultFormat = "%d(%F %T.%l) %c %-6V (%c:%F:%L) - %m%n",
    .filePerms = 0600,
    .fsyncPeriod = 0,
    .format_properties = NULL,
    .rule_properties = NULL,
};

int main(int argc, char *argv[])
{
    int rc;

    zlog_category_t *c;

    struct log_format_properties_listelem log_fmt1 = {
        .name = "simple",
        .pattern = "%d %m%n",
        .next = NULL,
    };

    struct log_format_properties_listelem log_fmt2 = {
        .name = "normal",
        .pattern = "%d(%F %T.%l) %m%n",
        .next = NULL,
    };

    struct log_rule_properties_listelem log_rule1 = {
        .archiveMaxCount = 10,
        .archiveMaxSize = 10 * 1024 * 1024,
        .archivePattern = "%E(HOME)/log/%c.%D(%F) #2r #3s.log",
        .category = "*",
        .level = "*",
        .formatName = "simple",
        .filePath = "%12.2E(HOME)/%c.log",
        .next = NULL,
    };

    struct log_rule_properties_listelem log_rule2 = {
        .archiveMaxCount = 10,
        .archiveMaxSize = 10 * 1024 * 1024,
        .archivePattern = "%E(HOME)/log/%c.%D(%F) #2r #3s.log",
        .category = "my",
        .level = "*",
        .formatName = "simple",
        .filePath = "stderr",
        .next = NULL,
    };

    add_format_property(&logcfg.format_properties, &log_fmt1);
    add_format_property(&logcfg.format_properties, &log_fmt2);

    add_rule_property(&logcfg.rule_properties, &log_rule1);
    add_rule_property(&logcfg.rule_properties, &log_rule2);

    rc = zlog_init(&logcfg);
    if (rc) {
        printf("init failed\n");
        return -1;
    }

    c = zlog_get_category("my");
    if (!c) {
        printf("get cat fail\n");
        zlog_fini();
        return -2;
    }

    zlog_info(c, "hello, zlog");
    zlog_info(c, "hello, zlog");

    zlog_fini();

    return 0;
}
