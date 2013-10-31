#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x887b4cdc, "module_layout" },
	{ 0xa60f9d25, "remove_proc_entry" },
	{ 0x3021c756, "create_proc_entry" },
	{ 0x37a0cba, "kfree" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x167e7f9d, "__get_user_1" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x9f317dd2, "kmem_cache_alloc_trace" },
	{ 0x87d48e3e, "kmalloc_caches" },
	{ 0x78dc9ef1, "dev_add_pack" },
	{ 0x27e1a049, "printk" },
	{ 0x62c9aaf9, "dev_remove_pack" },
	{ 0x91715312, "sprintf" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "7FBD56DB741BE974C080849");
