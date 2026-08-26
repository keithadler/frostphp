<?php

declare(strict_types=1);

namespace Frost\Extract;

use PhpParser\Node;

/**
 * The source text of a node, and where it starts.
 *
 * Slicing the original bytes rather than pretty-printing the tree matters for
 * a report someone has to act on: the line says what they wrote, quotes and
 * spacing and all, so they can find it by eye in the file.
 */
final class Snippet
{
    /** @var list<int> byte offset at which each line starts */
    private array $lineStarts;

    /** @param list<array{int, int}> $shifts [offset in this text, bytes added before it] */
    public function __construct(private readonly string $code, private readonly array $shifts = [])
    {
        $this->lineStarts = [0];
        $length = strlen($code);
        for ($i = 0; $i < $length; $i++) {
            if ($code[$i] === "\n") {
                $this->lineStarts[] = $i + 1;
            }
        }
    }

    /** 0-based column of a node's first byte. */
    public function column(Node $node): int
    {
        $pos = $node->getStartFilePos();
        if ($pos < 0) {
            return 0;
        }
        $line = $node->getStartLine();
        $start = $this->lineStarts[$line - 1] ?? 0;

        return max(0, ($pos - $start) - $this->shiftAt($pos) + $this->shiftAt($start));
    }

    /** How many bytes were inserted before this offset by tag rewriting. */
    private function shiftAt(int $offset): int
    {
        $shift = 0;
        foreach ($this->shifts as [$at, $total]) {
            if ($at > $offset) {
                break;
            }
            $shift = $total;
        }

        return $shift;
    }

    /** The node's own source, whitespace collapsed, clipped to one readable line. */
    public function text(Node $node, int $limit = 110): string
    {
        $start = $node->getStartFilePos();
        $end = $node->getEndFilePos();
        if ($start < 0 || $end < $start) {
            return '';
        }
        $raw = substr($this->code, $start, $end - $start + 1);
        $flat = trim((string) preg_replace('/\s+/', ' ', $raw));

        return strlen($flat) > $limit ? substr($flat, 0, $limit - 3) . '...' : $flat;
    }
}
