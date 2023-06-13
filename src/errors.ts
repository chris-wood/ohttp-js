/**
 * The base error class of ohttp-js.
 */
class OhttpError extends Error {
  public constructor(e: unknown) {
    let message: string;

    if (e instanceof Error) {
      message = e.message;
    } else if (typeof e === "string") {
      message = e;
    } else {
      message = "";
    }
    super(message);

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = this.constructor.name;
    if (this.message === "") {
      this.message = this.name;
    } else {
      this.message = this.name + ": " + this.message;
    }
  }
}

/**
 * Invalid (or unsupported) HPKE ciphersuite.
 */
export class InvalidHpkeCiphersuiteError extends OhttpError {}

/**
 * Invalid key configuration ID.
 */
export class InvalidConfigIdError extends OhttpError {}

/**
 * Invalid content type.
 */
export class InvalidContentTypeError extends OhttpError {}

/**
 * Invalid message encoding.
 */
export class InvalidEncodingError extends OhttpError {}

/**
 * A TBD failure or error.
 */
export class TodoError extends OhttpError {}

/**
 * Not supported failure.
 */
export class NotSupportedError extends OhttpError {}
