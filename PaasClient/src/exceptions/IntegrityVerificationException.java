package exceptions;

public class IntegrityVerificationException extends Exception {
	
	private static final long serialVersionUID = 1L;
	private static final String MESSAGE = "Integrity verification failed.";
	
	public IntegrityVerificationException() {
		super(MESSAGE);
	}

}
