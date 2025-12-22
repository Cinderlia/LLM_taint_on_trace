from . import ast_var

def process(taint, ctx):
    return ast_var.process(taint, ctx)
