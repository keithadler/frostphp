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

    /** @var list<list<array{int, int}>> one entry per preparation pass */
    private array $maps;

    /**
     * @param list<array{int, int}>|list<list<array{int, int}>> $shifts one map of
     *        [offset, bytes inserted before it], or several when the source was
     *        prepared more than once: a Blade template becomes PHP, and that PHP
     *        may in principle still have its open tags rewritten.
     */
    public function __construct(private readonly string $code, array $shifts = [])
    {
        // One map, or a list of them. Both shapes are accepted so callers that
        // only ever run a single pass do not have to wrap it. A map's entries
        // are [int, int] pairs, so a first element whose own first element is
        // an array can only be a list of maps.
        if ($shifts === []) {
            $this->maps = [];
        } elseif (is_array($shifts[0][0] ?? null)) {
            $this->maps = array_values(array_filter($shifts, static fn (array $m): bool => $m !== []));
        } else {
            $this->maps = [$shifts];
        }
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

    /**
     * How many bytes the preparation passes inserted before this offset.
     *
     * Each pass contributes its own cumulative count. Where two passes both
     * rewrote the same file the second one's offsets are in the first one's
     * output rather than the original, which makes this an approximation - but
     * only for a file that is both a Blade template and full of short open
     * tags, and only in the column. No pass ever adds or removes a newline, so
     * the line is always exact.
     */
    private function shiftAt(int $offset): int
    {
        $shift = 0;
        foreach ($this->maps as $map) {
            // Each entry holds the running total for its pass, so the last one
            // at or before this offset is that pass's whole contribution.
            $fromThisPass = 0;
            foreach ($map as [$at, $total]) {
                if ($at > $offset) {
                    break;
                }
                $fromThisPass = $total;
            }
            $shift += $fromThisPass;
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
