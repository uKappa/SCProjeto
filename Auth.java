public enum Auth{
    PASSWORD_NO_MATCH("Wrong password, please try again!"),
    NEW_USER("Successful registration"),
    OK_USER("Successful authentication"),
    ERROR("Error occured!");

    private final String message;

    Auth(String message) {
        this.message = message;
    }

    public String getMessage() {
        return this.message;
    }
}