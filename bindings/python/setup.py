from distutils.core import setup, Extension

scsmodule = Extension('scs',
        include_dirs = 
            ['../../include'],
        sources = 
            ['src/scsmodule.c'],
        libraries = 
            [ 'scs' ])

setup (name = 'scs',
        version = '0.0',
        description = 'Reference implementation of the SCS protocol',
        ext_modules = [scsmodule])
