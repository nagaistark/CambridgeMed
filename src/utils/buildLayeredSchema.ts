import {
   pipe,
   strictObject,
   type BaseIssue,
   type GenericSchema,
   type PipeItem,
   type StrictObjectSchema,
} from 'valibot';

// ── The "dual leaf" marker ──────────────────────────────────────────────────────
const DUAL_BRAND: unique symbol = Symbol('dual-leaf');

export interface DualLeaf<
   TInputSchema extends GenericSchema,
   TDocumentSchema extends GenericSchema,
> {
   readonly [DUAL_BRAND]: true;
   readonly input: TInputSchema;
   readonly document: TDocumentSchema;
}

export function dual<
   TInputSchema extends GenericSchema,
   TDocumentSchema extends GenericSchema,
>(
   input: TInputSchema,
   document: TDocumentSchema
): DualLeaf<TInputSchema, TDocumentSchema> {
   return { [DUAL_BRAND]: true, input, document };
}

export type Layer = 'input' | 'document';

// ── The "checked branch" marker ─────────────────────────────────────────────────
// Attaches cross-field validation actions (check, forward, custom...) directly
// to a subtree in the shape tree, in place. Since check() and forward() never
// transform their input (TInput === TOutput on every ValidationAction),
// wrapping a branch in checked() never changes what InferOutput reports for
// it — so ResolveShape can simply recurse into innerShape and ignore the
// actions at the type level.
const CHECKED_BRAND: unique symbol = Symbol('checked-branch');

// Any Valibot pipe item that doesn't change the type of its input: check(),
// forward(check(...)), custom(), rawCheck() — anything pipe() accepts that
// preserves TInput === TOutput. Typed as PipeItem<unknown, unknown, ...>
// because at the point these are stored in the array, the builder hasn't
// resolved the inner schema yet, so the concrete input type isn't known.
type ValidationAction = PipeItem<unknown, unknown, BaseIssue<unknown>>;

export interface CheckedBranch<TInnerShape> {
   readonly [CHECKED_BRAND]: true;
   readonly innerShape: TInnerShape;
   // Static array: same actions applied on both input and document layers.
   // Function of layer: for the rare case where a cross-field check genuinely
   // needs different logic per layer (e.g. real Date arithmetic vs string
   // comparison on a dual()-typed date field).
   readonly actions:
      | readonly ValidationAction[]
      | ((layer: Layer) => readonly ValidationAction[]);
}

export function checked<
   TInnerShape extends { readonly [key: string]: unknown },
>(
   innerShape: TInnerShape,
   actions:
      | readonly ValidationAction[]
      | ((layer: Layer) => readonly ValidationAction[])
): CheckedBranch<TInnerShape> {
   return { [CHECKED_BRAND]: true, innerShape, actions };
}

// ── The shape tree type ─────────────────────────────────────────────────────────
// Branch case is { [key: string]: unknown } rather than { [key: string]: Shape }
// to prevent TypeScript from validating the unbounded self-referential type
// against Valibot's ObjectEntries constraints before any concrete shape exists.
// All recursive precision lives in ResolveShape, which only evaluates against
// your actual literal shape objects.
export type Shape =
   | GenericSchema
   | DualLeaf<GenericSchema, GenericSchema>
   | CheckedBranch<unknown>
   | { readonly [key: string]: unknown };

// ── Type-level resolution ──────────────────────────────────────────────────────
// Given a shape tree node and a layer, produces the exact Valibot schema type
// that buildLayeredSchema will return for it at runtime.
export type ResolveShape<TNode, TLayer extends Layer> =
   TNode extends DualLeaf<infer TInputSchema, infer TDocumentSchema>
      ? TLayer extends 'input'
         ? TInputSchema
         : TDocumentSchema
      : TNode extends CheckedBranch<infer TInnerShape>
        ? ResolveShape<TInnerShape, TLayer>
        : TNode extends GenericSchema
          ? TNode
          : TNode extends { readonly [key: string]: unknown }
            ? StrictObjectSchema<
                 {
                    readonly [K in keyof TNode]: ResolveShape<TNode[K], TLayer>;
                 },
                 undefined
              >
            : never;

// ── Runtime discriminators ───────────────────────────────────────────────────────
// Each function checks for its brand symbol — the only reliable way to tell
// these plain objects apart from each other and from real Valibot schemas.

function isDualLeaf(
   value: unknown
): value is DualLeaf<GenericSchema, GenericSchema> {
   return typeof value === 'object' && value !== null && DUAL_BRAND in value;
}

function isCheckedBranch(value: unknown): value is CheckedBranch<unknown> {
   return typeof value === 'object' && value !== null && CHECKED_BRAND in value;
}

function isSchema(value: unknown): value is GenericSchema {
   return (
      typeof value === 'object' &&
      value !== null &&
      'kind' in value &&
      value.kind === 'schema'
   );
}

function isPlainShapeObject(
   value: unknown
): value is { readonly [key: string]: unknown } {
   return (
      typeof value === 'object' &&
      value !== null &&
      !isDualLeaf(value) &&
      !isCheckedBranch(value) &&
      !isSchema(value)
   );
}

// ── The builder ───────────────────────────────────────────────────────────────────
// Overload #1 — the public signature. TShape is inferred from the literal shape
// object you pass in, so the return type is the exact resolved schema for that
// tree and layer. This is what callers and InferOutput see.
export function buildLayeredSchema<
   const TShape extends Shape,
   TLayer extends Layer,
>(shape: TShape, layer: TLayer): ResolveShape<TShape, TLayer>;

// Overload #2 — the implementation signature. Intentionally loose: the body
// branches on runtime checks that TypeScript cannot fold back into a guarantee
// about the generic return type. Callers never resolve against this signature.
export function buildLayeredSchema(
   shape: unknown,
   layer: Layer
): GenericSchema {
   return resolveNode(shape, layer);
}

// The actual recursive worker, kept separate from the exported function because
// a function calling its own overloaded name recursively always resolves against
// the PUBLIC overload (#1), not the loose implementation signature — which would
// cause a type error on every recursive call.
function resolveNode(shape: unknown, layer: Layer): GenericSchema {
   if (isDualLeaf(shape)) {
      return layer === 'input' ? shape.input : shape.document;
   }

   if (isCheckedBranch(shape)) {
      const innerSchema = resolveNode(shape.innerShape, layer);
      const actions =
         typeof shape.actions === 'function'
            ? shape.actions(layer)
            : shape.actions;
      return pipe(innerSchema, ...actions);
   }

   if (isSchema(shape)) {
      return shape;
   }

   if (isPlainShapeObject(shape)) {
      const builtEntries: Record<string, GenericSchema> = {};
      for (const [key, value] of Object.entries(shape)) {
         builtEntries[key] = resolveNode(value, layer);
      }
      return strictObject(builtEntries);
   }

   throw new Error(
      `buildLayeredSchema: encountered a shape node that is neither a dual() leaf, ` +
         `a checked() branch, a Valibot schema, nor a plain nested object. ` +
         `This indicates a malformed shape tree.`
   );
}
