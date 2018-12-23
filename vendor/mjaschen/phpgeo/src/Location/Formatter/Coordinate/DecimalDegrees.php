<?php
declare(strict_types=1);

/**
 * Coordinate Formatter "Decimal Degrees"
 *
 * @author    Marcus Jaschen <mjaschen@gmail.com>
 * @license   https://opensource.org/licenses/MIT
 * @link      https://github.com/mjaschen/phpgeo
 */

namespace Location\Formatter\Coordinate;

use Location\Coordinate;

/**
 * Coordinate Formatter "Decimal Degrees"
 *
 * @author   Marcus Jaschen <mjaschen@gmail.com>
 * @license  https://opensource.org/licenses/MIT
 * @link     https://github.com/mjaschen/phpgeo
 */
class DecimalDegrees implements FormatterInterface
{
    /**
     * @var string Separator string between latitude and longitude
     */
    protected $separator;

    /**
     * @var int
     */
    protected $digits = 5;

    /**
     * @param string $separator
     * @param int $digits
     */
    public function __construct(string $separator = ' ', int $digits = 5)
    {
        $this->setSeparator($separator);
        $this->digits = $digits;
    }

    /**
     * @param Coordinate $coordinate
     *
     * @return string
     */
    public function format(Coordinate $coordinate): string
    {
        return sprintf(
            "%.{$this->digits}f%s%.{$this->digits}f",
            $coordinate->getLat(),
            $this->separator,
            $coordinate->getLng()
        );
    }

    /**
     * Sets the separator between latitude and longitude values
     *
     * @param $separator
     *
     * @return $this
     */
    public function setSeparator(string $separator): DecimalDegrees
    {
        $this->separator = $separator;

        return $this;
    }
}
