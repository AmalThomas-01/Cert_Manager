from pkscenroll import enrollment
from renewalfunc import renewal
from server import connect
import os

print("Server Starting..........")

filename = "servercert.pem"

if os.path.exists(filename):
    renewal()

def menu():
    print("           MENU\n")
    print("1.Start Server\n")
    print("2.Renew Certificate\n")
    print("3.Enroll Certificate\n")
    print("4:Exit")
    
    while True:
        choice = input("Enter your choice (1-4): ")
        if choice in ('1', '2', '3', '4'):
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

    return int(choice)


def main():
  while True:
    choice = menu()
    if choice == 1:
      # Implement functionality for connecting to clients
      print("Connecting...")
      connect()
    elif choice == 2:
      # Implement functionality for renewing certificate
      renewal()
    elif choice == 3:
      # Implement functionality for enrolling certificate

      enrollment("NEW")
      
    elif choice == 4:
      print("Exiting program.")
      break        


main()
