project('injector', 'cpp')
incdir = include_directories('../../easyhook')

comp = meson.get_compiler('cpp')
easyhook_dir = join_paths(meson.current_source_dir(), '../../easyhook')
message(easyhook_dir)
dep = comp.find_library('easyhook32',dirs : [easyhook_dir])
xd = declare_dependency(dependencies : [dep], include_directories : incdir) 
src = 'injector.cpp'
executable('injector', src, dependencies: xd)
src = 'inject.cpp'
shared_library('inject', src, dependencies: xd)

