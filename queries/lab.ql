/** 
 * @kind path-problem 
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation invocation |
      invocation.getMacro().getName().regexpMatch("ntoh.*") and
      invocation.getExpr() = this
    )
  }
}

module MyConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(Expr e | source.asExpr() = e and e instanceof NetworkByteSwap)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().hasName("memcpy") and
      sink.asExpr() = call.getArgument(2)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr().getEnclosingStmt() instanceof IfStmt
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
select sink, source, "Network byte swap flows to memcpy"