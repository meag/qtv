project('qtv', 'c')

qtv_sources = [
	'qtv/ban.c',
	'qtv/build.c',
	'qtv/cl_cmds.c',
	'qtv/cmd.c',
	'qtv/crc.c',
	'qtv/cvar.c',
	'qtv/forward.c',
	'qtv/forward_pending.c',
	'qtv/fs.c',
	'qtv/httpsv.c',
	'qtv/httpsv_generate.c',
	'qtv/info.c',
	'qtv/main.c',
	'qtv/mdfour.c',
	'qtv/msg.c',
	'qtv/net_utils.c',
	'qtv/parse.c',
	'qtv/qw.c',
	'qtv/source.c',
	'qtv/source_cmds.c',
	'qtv/sys.c',
	'qtv/token.c',
	'qtv/udp.c'
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

