package rules

import "embed"

// FS contains the built-in rules shipped with installed Vanguard binaries.
//
//go:embed cakephp/*.yaml codeigniter/*.yaml codeigniter4/*.yaml common/*.yaml laravel/*.yaml symfony/*.yaml wordpress/*.yaml yii2/*.yaml
var FS embed.FS
