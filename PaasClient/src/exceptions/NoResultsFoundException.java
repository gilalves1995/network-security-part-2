package exceptions;

public class NoResultsFoundException extends Exception {
	
	private static final long serialVersionUID = 1L;
	private static final String MESSAGE = "No results were found in database.";
	
	public NoResultsFoundException() {
		super(MESSAGE);
	}
	


}