package exceptions;

public class WrongOPCodeException extends Exception {
	
	private static final long serialVersionUID = 1L;
	private static final String MESSAGE = "Wrong operation code detected.";
	
	public WrongOPCodeException() {
		super(MESSAGE);
	}
}
