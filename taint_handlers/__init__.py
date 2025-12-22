from . import ast_var
from . import ast_prop
from . import ast_dim
from . import ast_method_call
from . import ast_call

REGISTRY = {
    'AST_VAR': ast_var.process,
    'AST_PROP': ast_prop.process,
    'AST_DIM': ast_dim.process,
    'AST_METHOD_CALL': ast_method_call.process,
    'AST_CALL': ast_call.process
}
