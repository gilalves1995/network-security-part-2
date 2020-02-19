package paas_client;
import java.util.*;

public class LocalIndex {

    public static final int CC = 0;
    public static final int EMISSION_DATE = 1;
    public static final int SALARY = 2;
    public static final int DEPARTMENT = 3;
    public static final int NIF = 4;

    private Map<String, List<String>>[] index;

    @SuppressWarnings("unchecked")
	public LocalIndex(int size) {
        index = new Map[5];
        for (int i = CC; i < NIF +1; i++) {
            index[i] = new HashMap<>(size);
        }
    }

    public String getCc(String cc) {
        List<String> l = index[CC].get(cc);
        if (l == null || l.isEmpty())
            return null;

        return l.get(0);
    }

    public void setCc(String cc, String key) {
        if (index[CC].get(cc) == null)
            index[CC].put(cc, new ArrayList<>());

        index[CC].get(cc).add(key);
    }

    public String getNif(String nif) {
        List<String> l = index[NIF].get(nif);
        if (l == null || l.isEmpty())
            return null;

        return l.get(0);
    }

    public void setNif(String nif, String key) {
        if (index[NIF].get(nif) == null)
            index[NIF].put(nif, new ArrayList<>());

        index[NIF].get(nif).add(key);
    }

    public List<String> getEmissionDate(String date) {
        List<String> l = index[EMISSION_DATE].get(date);
        return l != null ? l : new ArrayList<>(0);
    }

    public void setEmissionDate(String date, String key) {
        if (index[EMISSION_DATE].get(date) == null)
            index[EMISSION_DATE].put(date, new ArrayList<>());

        index[EMISSION_DATE].get(date).add(key);
    }

    public List<String> getSalary(String salary) {
        List<String> l = index[SALARY].get(salary);
        return l != null ? l : new ArrayList<>(0);
    }

    public List<String> getSalary(int salary) {
        return getSalary("" + salary);
    }

    public void setSalary(String salary, String key) {
        if (index[SALARY].get(salary) == null)
            index[SALARY].put(salary, new ArrayList<>());

        index[SALARY].get(salary).add(key);
    }

    public List<String> getDepartment(String department) {
        List<String> l = index[DEPARTMENT].get(department);
        return l != null ? l : new ArrayList<>(0);
    }

    public void setDepartment(String department, String key) {
        if (index[DEPARTMENT].get(department) == null)
            index[DEPARTMENT].put(department, new ArrayList<>());

        index[DEPARTMENT].get(department).add(key);
    }

    public Set<String> getAllPrimaryKeys() {
        return index[CC].keySet();
    }

    public List<String> getKeys(int field, String fieldValue) {
        return index[field].get(fieldValue);
    }

}