package exceptions;

public class AuthenticityVerificationException extends Exception {
	
	private static final long serialVersionUID = 1L;
	private static final String MESSAGE = "Authenticity verification failed.";
	
	public AuthenticityVerificationException() {
		super(MESSAGE);
	}

}
