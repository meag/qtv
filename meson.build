project('qtv', 'c')

qtv_sources = [
	'gban.c',
	'gbuild.c',
	'gcl_cmds.c',
	'gcmd.c',
	'gcrc.c',
	'gcvar.c',
	'gforward.c',
	'gforward_pending.c',
	'gfs.c',
	'ghttpsv.c',
	'ghttpsv_generate.c',
	'ginfo.c',
	'gmain.c',
	'gmdfour.c',
	'gmsg.c',
	'gnet_utils.c',
	'gparse.c',
	'gqw.c',
	'gsource.c',
	'gsource_cmds.c',
	'gsys.c',
	'gtoken.c',
	'gudp.c'
]

c_args = []

library('qtv', qtv_sources,
	include_directories : include_directories('.'),
	c_args : c_args,
	dependencies : [
		meson.get_compiler('c').find_library('m', required : false)
	],
	name_prefix : ''
)

