<?php
declare(strict_types=1);

/**
 * Coordinate Factory
 *
 * @author   Marcus Jaschen <mjaschen@gmail.com>
 * @license  https://opensource.org/licenses/MIT
 * @link     https://github.com/mjaschen/phpgeo
 */

namespace Location\Factory;

use Location\Coordinate;
use Location\Ellipsoid;

/**
 * Coordinate Factory
 *
 * @author   Marcus Jaschen <mjaschen@gmail.com>
 * @license  https://opensource.org/licenses/MIT
 * @link     https://github.com/mjaschen/phpgeo
 */
class CoordinateFactory implements GeometryFactoryInterface
{
    /**
     * Creates a Coordinate instance from the given string.
     *
     * The string is parsed by a regular expression for a known
     * format of geographical coordinates.
     *
     * @param string $string formatted geographical coordinate
     * @param \Location\Ellipsoid $ellipsoid
     *
     * @return Coordinate
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $string, Ellipsoid $ellipsoid = null): Coordinate
    {
        $result = self::parseDecimalMinutesWithoutCardinalLetters($string, $ellipsoid);

        if ($result instanceof Coordinate) {
            return $result;
        }

        $result = self::parseDecimalMinutesWithCardinalLetters($string, $ellipsoid);

        if ($result instanceof Coordinate) {
            return $result;
        }

        $result = self::parseDecimalDegreesWithoutCardinalLetters($string, $ellipsoid);

        if ($result instanceof Coordinate) {
            return $result;
        }

        $result = self::parseDecimalDegreesWithCardinalLetters($string, $ellipsoid);

        if ($result instanceof Coordinate) {
            return $result;
        }

        throw new \InvalidArgumentException('Format of coordinates was not recognized');
    }

    /**
     * @param $string
     * @param $ellipsoid
     *
     * @return Coordinate|null
     * @throws \InvalidArgumentException
     */
    private static function parseDecimalMinutesWithoutCardinalLetters(string $string, Ellipsoid $ellipsoid = null)
    {
        // Decimal minutes without cardinal letters, e. g. "52 12.345, 13 23.456",
        // "52° 12.345, 13° 23.456", "52° 12.345′, 13° 23.456′", "52 12.345 N, 13 23.456 E",
        // "N52° 12.345′ E13° 23.456′"
        if (preg_match('/(-?\d{1,2})°?\s+(\d{1,2}\.?\d*)[\'′]?[, ]\s*(-?\d{1,3})°?\s+(\d{1,2}\.?\d*)[\'′]?/ui', $string, $match)) {
            $latitude = $match[1] >= 0 ? $match[1] + $match[2] / 60 : $match[1] - $match[2] / 60;
            $longitude = $match[3] >= 0 ? $match[3] + $match[4] / 60 : $match[3] - $match[4] / 60;

            return new Coordinate((float)$latitude, (float)$longitude, $ellipsoid);
        }

        return null;
    }

    /**
     * @param $string
     * @param $ellipsoid
     *
     * @return Coordinate|null
     * @throws \InvalidArgumentException
     */
    private static function parseDecimalMinutesWithCardinalLetters(string $string, Ellipsoid $ellipsoid = null)
    {
        // Decimal minutes with cardinal letters, e. g. "52 12.345, 13 23.456",
        // "52° 12.345, 13° 23.456", "52° 12.345′, 13° 23.456′", "52 12.345 N, 13 23.456 E",
        // "N52° 12.345′ E13° 23.456′"
        if (preg_match('/([NS]?\s*)(\d{1,2})°?\s+(\d{1,2}\.?\d*)[\'′]?(\s*[NS]?)[, ]\s*([EW]?\s*)(\d{1,3})°?\s+(\d{1,2}\.?\d*)[\'′]?(\s*[EW]?)/ui', $string, $match)) {
            $latitude = $match[2] + $match[3] / 60;
            if (strtoupper(trim($match[1])) === 'S' || strtoupper(trim($match[4])) === 'S') {
                $latitude = - $latitude;
            }
            $longitude = $match[6] + $match[7] / 60;
            if (strtoupper(trim($match[5])) === 'W' || strtoupper(trim($match[8])) === 'W') {
                $longitude = - $longitude;
            }

            return new Coordinate((float)$latitude, (float)$longitude, $ellipsoid);
        }

        return null;
    }

    /**
     * @param $string
     * @param $ellipsoid
     *
     * @return Coordinate|null
     * @throws \InvalidArgumentException
     */
    private static function parseDecimalDegreesWithoutCardinalLetters(string $string, Ellipsoid $ellipsoid = null)
    {
        // The most simple format: decimal degrees without cardinal letters,
        // e. g. "52.5, 13.5" or "53.25732 14.24984"
        if (preg_match('/(-?\d{1,2}\.?\d*)°?[, ]\s*(-?\d{1,3}\.?\d*)°?/u', $string, $match)) {
            return new Coordinate((float)$match[1], (float)$match[2], $ellipsoid);
        }

        return null;
    }

    /**
     * @param $string
     * @param $ellipsoid
     *
     * @return Coordinate|null
     * @throws \InvalidArgumentException
     */
    private static function parseDecimalDegreesWithCardinalLetters(string $string, Ellipsoid $ellipsoid = null)
    {
        // Decimal degrees with cardinal letters, e. g. "N52.5, E13.5",
        // "40.2S, 135.3485W", or "56.234°N, 157.245°W"
        if (preg_match('/([NS]?\s*)(\d{1,2}\.?\d*)°?(\s*[NS]?)[, ]\s*([EW]?\s*)(\d{1,3}\.?\d*)°?(\s*[EW]?)/ui', $string, $match)) {
            $latitude = $match[2];
            if (strtoupper(trim($match[1])) === 'S' || strtoupper(trim($match[3])) === 'S') {
                $latitude = - $latitude;
            }
            $longitude = $match[5];
            if (strtoupper(trim($match[4])) === 'W' || strtoupper(trim($match[6])) === 'W') {
                $longitude = - $longitude;
            }

            return new Coordinate((float)$latitude, (float)$longitude, $ellipsoid);
        }

        return null;
    }
}
