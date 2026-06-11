/**
 * Rule condition evaluator
 * Supports both simple leaf conditions (SPEC-001 §4.2) and AST expressions (§4.5)
 */

import type { Condition, SimpleCondition, ASTExpr, Json } from './types';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getNestedValue(ctx: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((curr, key) => {
    if (curr === null || curr === undefined) return undefined;
    return (curr as Record<string, unknown>)[key];
  }, ctx);
}

function isSimpleCondition(c: Condition): c is SimpleCondition {
  return 'field' in c && 'op' in c;
}

// ─── Simple condition evaluation ─────────────────────────────────────────────

function evalSimple(cond: SimpleCondition, ctx: Record<string, unknown>): boolean {
  const actual = getNestedValue(ctx, cond.field);
  const expected = cond.value;

  switch (cond.op) {
    case 'exists':
      return actual !== undefined && actual !== null;
    case 'eq':
      return actual == expected; // intentional loose equality for number/string coercion
    case 'neq':
      return actual != expected;
    case 'gt':
      return typeof actual === 'number' && typeof expected === 'number' && actual > expected;
    case 'gte':
      return typeof actual === 'number' && typeof expected === 'number' && actual >= expected;
    case 'lt':
      return typeof actual === 'number' && typeof expected === 'number' && actual < expected;
    case 'lte':
      return typeof actual === 'number' && typeof expected === 'number' && actual <= expected;
    case 'in':
      return Array.isArray(expected) && expected.includes(actual as Json);
    case 'nin':
      return Array.isArray(expected) && !expected.includes(actual as Json);
    case 'regex': {
      if (typeof actual !== 'string' || typeof expected !== 'string') return false;
      try { return new RegExp(expected).test(actual); } catch { return false; }
    }
    default:
      return false;
  }
}

// ─── AST expression evaluation ───────────────────────────────────────────────

function evalAST(expr: ASTExpr, ctx: Record<string, unknown>): Json {
  if ('lit' in expr) return expr.lit;

  if ('ref' in expr) {
    const val = getNestedValue(ctx, expr.ref);
    return val === undefined ? null : (val as Json);
  }

  if ('fn' in expr) {
    const args = expr.args.map(a => evalAST(a, ctx));
    switch (expr.fn) {
      case 'exists':   return args[0] !== null && args[0] !== undefined;
      case 'len':      return typeof args[0] === 'string' ? args[0].length : Array.isArray(args[0]) ? args[0].length : 0;
      case 'lower':    return typeof args[0] === 'string' ? args[0].toLowerCase() : args[0];
      case 'starts_with': return typeof args[0] === 'string' && typeof args[1] === 'string' && args[0].startsWith(args[1]);
      case 'ends_with':   return typeof args[0] === 'string' && typeof args[1] === 'string' && args[0].endsWith(args[1]);
      case 'matches': {
        if (typeof args[0] !== 'string' || typeof args[1] !== 'string') return false;
        try { return new RegExp(args[1]).test(args[0]); } catch { return false; }
      }
      case 'coalesce': return args.find(a => a !== null && a !== undefined) ?? null;
      default: return null;
    }
  }

  if ('op' in expr) {
    // Short-circuit logical operators
    if (expr.op === 'and') {
      for (const arg of expr.args) { if (!evalAST(arg, ctx)) return false; }
      return true;
    }
    if (expr.op === 'or') {
      for (const arg of expr.args) { if (evalAST(arg, ctx)) return true; }
      return false;
    }
    if (expr.op === 'not') return !evalAST(expr.args[0], ctx);

    const args = expr.args.map(a => evalAST(a, ctx));
    switch (expr.op) {
      case '==':  return args[0] == args[1];
      case '!=':  return args[0] != args[1];
      case '>':   return (args[0] as number) > (args[1] as number);
      case '>=':  return (args[0] as number) >= (args[1] as number);
      case '<':   return (args[0] as number) < (args[1] as number);
      case '<=':  return (args[0] as number) <= (args[1] as number);
      case '+':   return (args[0] as number) + (args[1] as number);
      case '-':   return (args[0] as number) - (args[1] as number);
      case '*':   return (args[0] as number) * (args[1] as number);
      case '/':   return args[1] === 0 ? null : (args[0] as number) / (args[1] as number);
      case 'in':  return Array.isArray(args[1]) && args[1].includes(args[0]);
      case 'contains': return Array.isArray(args[0]) && args[0].includes(args[1]);
      default:    return null;
    }
  }

  return null;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Evaluate a rule condition against an execution context.
 * Returns true if the condition matches, false otherwise.
 * Unknown operators return false (caller escalates per §9.1 R4).
 */
export function evalCondition(condition: Condition, ctx: Record<string, unknown>): boolean {
  if (isSimpleCondition(condition)) {
    return evalSimple(condition, ctx);
  }
  const result = evalAST(condition as ASTExpr, ctx);
  return result === true;
}

/**
 * Check whether a condition uses any operators not defined in SPEC-001 §4.2.
 * Returns the list of unknown operators found (empty = all known).
 */
export function findUnknownOperators(condition: Condition): string[] {
  const known = new Set([
    'eq','neq','gt','gte','lt','lte','in','nin','exists','regex',
    'and','or','not','==','!=','>','>=','<','<=','+','-','*','/',
    'contains','fn:exists','fn:len','fn:lower','fn:starts_with',
    'fn:ends_with','fn:matches','fn:coalesce',
  ]);
  const unknown: string[] = [];

  function walk(node: Condition) {
    if ('op' in node && typeof node.op === 'string' && !known.has(node.op)) {
      unknown.push(node.op);
    }
    if ('fn' in node && typeof (node as ASTExpr & { fn?: string }).fn === 'string') {
      const fn = (node as { fn: string }).fn;
      if (!known.has('fn:' + fn)) unknown.push('fn:' + fn);
    }
    if ('args' in node && Array.isArray((node as { args?: unknown[] }).args)) {
      for (const arg of (node as { args: Condition[] }).args) walk(arg);
    }
    if ('left' in node) walk((node as unknown as { left: Condition }).left);
    if ('right' in node) walk((node as unknown as { right: Condition }).right);
  }

  walk(condition);
  return [...new Set(unknown)];
}
