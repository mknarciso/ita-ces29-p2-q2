package exe2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

public class VulnerableClass {
	// Valores setados pequenos apenas para demonstrar os erros que ocorrem
	private static int MAX_LINES = 10;
	private static int MAX_LINE_SIZE = 50;
	public void vulnerableMethod(String FILENAME) throws Exception{
		// Evitar o acesso a arquivos acima do diretório atual, evita a gravação ou leitura de arquivos do sistema
		if(FILENAME.matches("(.*)\\.\\.(.*)"))
			throw new Exception("Not allowed to acess parent directory");
		// Sanitiza o nome do arquivo, evitando caracteres especiais
		if(!FILENAME.matches("[A-Za-z0-9._/]*"))
			throw new Exception("Special characteres are not allowed");
		while (true) {
		    Scanner console = new Scanner(System.in);
		    // Coloca uma condição de parada para o programa, Q encerra a execução
		    System.out.print("Digite a operacao desejada para realizar no arquivo <R para ler um arquivo, "
		    		+ "W para escrever em um arquivo, Q para encerrar>? ");
			
		    String opr = console.nextLine();
			
		    if (opr.equals("R")){
		    	// Criadas antes de ser necessário
				// BufferedReader br = null;
				// FileReader fr = null;
				
				try {

					//fr = new FileReader(FILENAME); // Não utilizado
					//br = new BufferedReader(fr);
					BufferedReader br = new BufferedReader(new FileReader(FILENAME));;
					String sCurrentLine;
					// Setar um limite de tamanho de entrada para o arquivo
					int count = 0;
					while (((sCurrentLine = br.readLine()) != null)) {
						if(count<MAX_LINES){
							System.out.println(sCurrentLine);
							count++;
						} else {
							throw new Exception("File is bigger then allowed");
						}
					}
					// O buffer nunca era fechado
					br.close();
					
				} catch (IOException e) {
					e.printStackTrace();
				} 
			} else if(opr.equals("Q")){
				// Oferece uma forma de sair do programa, evitando que fique aberto indefinidamente
				System.out.println("Closing program...");
				console.close();
				return;
			} else if(opr.equals("W")) {
				  //BufferedWriter buffWrite;
				  try {
					 // Dado que o arquivo é reescrito a cada iteração não é necessário tratar seu tamanho total,
					 // Mas o tamanho da nova entrada
					FileWriter fw = new FileWriter(FILENAME);
					BufferedWriter buffWrite = new BufferedWriter(fw);
					String linha = "";
					System.out.println("Escreva algo: ");
					//Limitar o tamanho de entrada de cada linha, descartando o restante
				    //linha = console.nextLine();
					linha = console.nextLine(); 
				    //Sanitiza a linha entrada de acordo com regras desejadas, exemplo:
				    if(!linha.matches("[A-Za-z0-9._/\\n\\s]*")){
				    	buffWrite.close();
				    	throw new Exception("Invalid chars input!");
			    	}
				    if(linha.length()>MAX_LINE_SIZE){
				    	buffWrite.close();
				    	throw new Exception("Too much characters in the line!");
			    	}
				    buffWrite.append(linha + "\n");
				    // Buffer de saída não era fechado, além da segurança afetada, o conteúdo não era salvo
				    buffWrite.close();
				} catch (IOException e) {
					e.printStackTrace();
				} 
			} else {
				// Evita que uma sequncia não esperada entre no buffer, caso casos omissos seguissem a regra W
				System.out.println("Opção inválida");
			}
		}
	}
	
	/*public static void main(String[] args) throws Exception{
		VulnerableClass vc = new VulnerableClass();
		vc.vulnerableMethod("read.txt");
	}*/
	
}
