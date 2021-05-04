package visual;

public class Waiter implements Runnable { MessageWriter mw;
  
  public Waiter(MessageWriter m) { mw = m; }
  

  public void run()
  {
    System.out.print("Bitte warten Sie während die Tests ausgeführt werden");
    for (int i = 0; i < 10; i++) {
      try {
        Thread.sleep(250L);
      } catch (InterruptedException localInterruptedException) {}
      System.out.print(".");
      try {
        Thread.sleep(250L);
      } catch (InterruptedException localInterruptedException1) {}
      System.out.print(".");
      try {
        Thread.sleep(250L);
      } catch (InterruptedException localInterruptedException2) {}
      System.out.print(".");
      try {
        Thread.sleep(250L);
      } catch (InterruptedException localInterruptedException3) {}
      System.out.print("\b\b\b");
      System.out.print("   ");
      System.out.print("\b\b\b");
    }
    System.out.println("");
    System.out.println(mw.getMsg());
  }
}
