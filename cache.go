package msauth

import "errors"

// errLegacyPlaintext marks an unprotected file left by an earlier prototype.
// Such a file is removed rather than read, so callers treat it as a cold cache
// and re-acquire instead of inheriting unprotected credential material.
var errLegacyPlaintext = errors.New("removed legacy plaintext credential file")
