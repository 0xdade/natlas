from PIL import Image, UnidentifiedImageError


def is_valid_image(path: str) -> bool:
    try:
        Image.open(path)
        return True
    except (FileNotFoundError, UnidentifiedImageError):
        return False
