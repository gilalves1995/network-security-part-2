package exceptions;

public class UntrustablePlatformException extends Exception {
	
	private static final long serialVersionUID = 1L;
	private static final String MESSAGE = "Attestation proof failed. Platform is not secure. Abort.";
	
	public UntrustablePlatformException() {
		super(MESSAGE);
	}

}
