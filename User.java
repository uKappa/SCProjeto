public class User {
    private String userId;
    private int deviceId;
    private String imgName;
    private boolean conectado;

    public User(String userId, int deviceId, String imgName, boolean conectado) {
        this.userId = userId;
        this.deviceId = deviceId;
        this.imgName = imgName;
        this.conectado = conectado;
    }

    // Getters and setters
    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public int getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(int deviceId) {
        this.deviceId = deviceId;
    }

    public String getImgName() {
        return imgName;
    }

    public void setImgName(String imgName) {
        this.imgName = imgName;
    }

    @Override
    public String toString() {
        return "User{" +
                "userId='" + userId + '\'' +
                ", deviceId=" + deviceId +
                ", imgName='" + imgName + '\'' +
                '}';
    }

    public void setConectado(boolean b) {
        this.conectado = b;
    }

    public boolean isConectado() {
        return this.conectado;
    }
}
