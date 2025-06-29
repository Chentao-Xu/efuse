#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xd1ff2714, "class_destroy" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x37a0cba, "kfree" },
	{ 0x5a39467c, "fuse_sync_release" },
	{ 0x4c33b6f1, "fuse_conn_put" },
	{ 0x95ee770, "fuse_conn_get" },
	{ 0x1b96a6a0, "fuse_do_open" },
	{ 0xfe276933, "fuse_direct_io" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x5d3c30d3, "misc_deregister" },
	{ 0xed48e1d, "fuse_do_ioctl" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0x64d5e399, "__free_pages" },
	{ 0x97651e6c, "vmemmap_base" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0x754d539c, "strlen" },
	{ 0x85df9b6c, "strsep" },
	{ 0x77bc13a0, "strim" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x122c3a7e, "_printk" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x8e61b64d, "kmalloc_caches" },
	{ 0xf0a85575, "kmalloc_trace" },
	{ 0x3b57461, "device_initialize" },
	{ 0x336dc265, "dev_set_name" },
	{ 0x98e01611, "put_device" },
	{ 0x88e86daf, "device_add" },
	{ 0x3b4573fa, "cdev_alloc" },
	{ 0x19182dd7, "cdev_add" },
	{ 0xa53b361b, "kobject_uevent" },
	{ 0x3fd78f3b, "register_chrdev_region" },
	{ 0xeab38b22, "fuse_dev_fiq_ops" },
	{ 0xf20b4d8e, "fuse_conn_init" },
	{ 0x76acc235, "fuse_dev_alloc_install" },
	{ 0xdacc1a1e, "alloc_pages" },
	{ 0x5b207759, "fuse_simple_background" },
	{ 0x9933dd7e, "fuse_dev_free" },
	{ 0xfc01ea62, "noop_llseek" },
	{ 0xb8c5ca69, "fuse_file_poll" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x7e20f803, "fuse_abort_conn" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x4dfa8d4b, "mutex_lock" },
	{ 0x3213f038, "mutex_unlock" },
	{ 0xb461fe08, "device_unregister" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0xfa0ae47e, "cdev_del" },
	{ 0x19fcee30, "fuse_dev_release" },
	{ 0x44c10a52, "kvfree_call_rcu" },
	{ 0xf1110943, "fuse_dev_operations" },
	{ 0xc7efe48f, "class_create" },
	{ 0x32b89738, "misc_register" },
	{ 0x112425ee, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "15A95BF3246A888C3C0C5CD");
