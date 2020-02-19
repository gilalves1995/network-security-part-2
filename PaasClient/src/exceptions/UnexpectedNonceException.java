package exceptions;

public class UnexpectedNonceException extends Exception {
	
	private static final long serialVersionUID = 1L;
	private static final String MESSAGE = "Unexpected nonce was retrieved.";
	
	public UnexpectedNonceException() {
		super(MESSAGE);
	}

}
