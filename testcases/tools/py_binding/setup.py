from distutils.core import setup, Extension

def main():
    setup(name="sc",
          version="1.0.0",
          description="Python interface for split container",
          author="",
          author_email="",
          ext_modules=[Extension("sc", ["binding.c", "lean_container.c"])])

if __name__ == "__main__":
    main()